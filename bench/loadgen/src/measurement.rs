use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::{Id, JoinError, JoinSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MeasurementBoundary {
    Start,
    End,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ResourceSample {
    pub(crate) requested_at: Option<Instant>,
    pub(crate) sample_started_at: Option<Instant>,
    pub(crate) sampled_at: Option<Instant>,
    pub(crate) details: serde_json::Value,
}

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const EXACT_NS_LIMIT: u64 = 100_000;
const MAX_HISTOGRAM_NS: u64 = 1_000_000_000_000_000_000;
const DKW_95_EPSILON_FACTOR: f64 = 1.358_101_515_740_619_5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestOutcome {
    Http(u16),
    Transport,
    Timeout,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestSample {
    pub(crate) outcome: RequestOutcome,
    pub(crate) due_at: Instant,
    pub(crate) task_started_at: Instant,
    pub(crate) request_started_at: Instant,
    pub(crate) completed_at: Instant,
}

impl RequestSample {
    pub(crate) fn new(
        outcome: RequestOutcome,
        due_at: Instant,
        task_started_at: Instant,
        request_started_at: Instant,
        completed_at: Instant,
    ) -> Self {
        Self {
            outcome,
            due_at,
            task_started_at,
            request_started_at,
            completed_at,
        }
    }
}

struct InFlightGuard(Arc<AtomicU64>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

enum TrackedJoin<T> {
    Output(T),
    JoinError {
        due_at: Option<Instant>,
        error: JoinError,
    },
}

struct TrackedTasks<T> {
    tasks: JoinSet<T>,
    due_at_by_id: HashMap<Id, Instant>,
    active_count: Arc<AtomicU64>,
}

impl<T: Send + 'static> TrackedTasks<T> {
    fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            due_at_by_id: HashMap::new(),
            active_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn spawn<Fut>(&mut self, future: Fut, due_at: Instant)
    where
        Fut: Future<Output = T> + Send + 'static,
    {
        self.active_count.fetch_add(1, Ordering::SeqCst);
        let guard = InFlightGuard(Arc::clone(&self.active_count));
        let handle = self.tasks.spawn(async move {
            let _guard = guard;
            future.await
        });
        self.due_at_by_id.insert(handle.id(), due_at);
    }

    fn len(&self) -> usize {
        self.tasks.len()
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn active_count(&self) -> u64 {
        self.active_count.load(Ordering::SeqCst)
    }

    fn abort_all(&mut self) {
        self.tasks.abort_all();
    }

    fn take_result(&mut self, result: Result<(Id, T), JoinError>) -> TrackedJoin<T> {
        match result {
            Ok((id, output)) => {
                self.due_at_by_id.remove(&id);
                TrackedJoin::Output(output)
            }
            Err(error) => TrackedJoin::JoinError {
                due_at: self.due_at_by_id.remove(&error.id()),
                error,
            },
        }
    }

    async fn join_next(&mut self) -> Option<TrackedJoin<T>> {
        self.tasks
            .join_next_with_id()
            .await
            .map(|result| self.take_result(result))
    }

    fn try_join_next(&mut self) -> Option<TrackedJoin<T>> {
        self.tasks
            .try_join_next_with_id()
            .map(|result| self.take_result(result))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Histogram {
    upper_bounds_ns: Vec<u64>,
    counts: Vec<u64>,
    count: u64,
    sum_ns: u128,
    max_ns: u64,
}

impl Histogram {
    pub(crate) fn new() -> Self {
        let mut upper_bounds_ns = (0..=EXACT_NS_LIMIT).collect::<Vec<_>>();
        let mut upper = EXACT_NS_LIMIT + 1;
        while upper < MAX_HISTOGRAM_NS {
            upper = ((upper as f64 * 1.01).ceil() as u64)
                .max(upper.saturating_add(1))
                .min(MAX_HISTOGRAM_NS);
            upper_bounds_ns.push(upper);
        }
        let counts = vec![0; upper_bounds_ns.len()];
        Self {
            upper_bounds_ns,
            counts,
            count: 0,
            sum_ns: 0,
            max_ns: 0,
        }
    }

    pub(crate) fn record(&mut self, value_ns: u64) {
        let index = self
            .upper_bounds_ns
            .partition_point(|upper| *upper < value_ns)
            .min(self.counts.len() - 1);
        self.counts[index] = self.counts[index].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.sum_ns = self.sum_ns.saturating_add(u128::from(value_ns));
        self.max_ns = self.max_ns.max(value_ns);
    }

    pub(crate) fn count(&self) -> u64 {
        self.count
    }

    pub(crate) fn mean_ns(&self) -> Option<u64> {
        (self.count > 0).then(|| (self.sum_ns / u128::from(self.count)) as u64)
    }

    fn quantile_bounds(&self, percentile: f64) -> Option<(u64, u64)> {
        if self.count == 0 || !(0.0..=100.0).contains(&percentile) {
            return None;
        }
        let rank = ((self.count as f64 * percentile / 100.0).ceil() as u64).max(1);
        let index = self.index_at_rank(rank)?;
        Some((self.lower_bound_at(index), self.upper_bounds_ns[index]))
    }

    fn index_at_rank(&self, rank: u64) -> Option<usize> {
        if self.count == 0 || rank == 0 || rank > self.count {
            return None;
        }
        let mut cumulative = 0u64;
        for (index, count) in self.counts.iter().enumerate() {
            cumulative = cumulative.saturating_add(*count);
            if cumulative >= rank {
                return Some(index);
            }
        }
        None
    }

    fn lower_bound_at(&self, index: usize) -> u64 {
        if index == 0 {
            0
        } else {
            self.upper_bounds_ns[index - 1].saturating_add(1)
        }
    }

    pub(crate) fn percentile_ns(&self, percentile: f64) -> Option<u64> {
        self.quantile_bounds(percentile).map(|(_, upper)| upper)
    }

    pub(crate) fn percentile_ci95_ns(&self, percentile: f64) -> Option<(u64, u64)> {
        if self.count == 0 || !(0.0..=100.0).contains(&percentile) {
            return None;
        }
        let epsilon = DKW_95_EPSILON_FACTOR / (self.count as f64).sqrt();
        let low_p = (percentile / 100.0 - epsilon).max(0.0);
        let high_p = (percentile / 100.0 + epsilon).min(1.0);
        let low = if low_p <= 0.0 {
            0
        } else {
            let rank = (self.count as f64 * low_p).ceil() as u64;
            let index = self.index_at_rank(rank.max(1))?;
            self.lower_bound_at(index)
        };
        let high_rank = (self.count as f64 * high_p).ceil() as u64;
        let high_index = self.index_at_rank(high_rank.max(1).min(self.count))?;
        Some((low, self.upper_bounds_ns[high_index]))
    }

    pub(crate) fn percentile_ci95_relative_half_width(&self, percentile: f64) -> Option<f64> {
        let estimate = self.percentile_ns(percentile)?;
        if estimate == 0 {
            return None;
        }
        let (low, high) = self.percentile_ci95_ns(percentile)?;
        let lower_deviation = estimate.saturating_sub(low);
        let upper_deviation = high.saturating_sub(estimate);
        Some(lower_deviation.max(upper_deviation) as f64 / estimate as f64)
    }

    pub(crate) fn max_ns(&self) -> Option<u64> {
        (self.count > 0).then_some(self.max_ns)
    }

    pub(crate) fn nonempty_buckets(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.upper_bounds_ns
            .iter()
            .copied()
            .zip(self.counts.iter().copied())
            .filter(|(_, count)| *count > 0)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TimeBucket {
    pub(crate) start_ns: u64,
    pub(crate) end_ns: u64,
    pub(crate) scheduled: u64,
    pub(crate) started: u64,
    pub(crate) missed: u64,
    pub(crate) dropped: u64,
    pub(crate) aborted: u64,
    pub(crate) completed: u64,
    pub(crate) ok: u64,
    pub(crate) http_fail: u64,
    pub(crate) transport_err: u64,
    pub(crate) timeout_err: u64,
    pub(crate) worker_error: u64,
    pub(crate) cohort_completed: u64,
    pub(crate) cohort_ok: u64,
    pub(crate) cohort_failures: u64,
    pub(crate) cohort_worker_errors: u64,
    pub(crate) cohort_cancelled: u64,
    pub(crate) in_flight_end: i64,
}

impl TimeBucket {
    fn new(start_ns: u64, end_ns: u64) -> Self {
        Self {
            start_ns,
            end_ns,
            scheduled: 0,
            started: 0,
            missed: 0,
            dropped: 0,
            aborted: 0,
            completed: 0,
            ok: 0,
            http_fail: 0,
            transport_err: 0,
            timeout_err: 0,
            worker_error: 0,
            cohort_completed: 0,
            cohort_ok: 0,
            cohort_failures: 0,
            cohort_worker_errors: 0,
            cohort_cancelled: 0,
            in_flight_end: 0,
        }
    }
}

pub(crate) struct Stats {
    pub(crate) scheduled: u64,
    pub(crate) started: u64,
    pub(crate) missed: u64,
    pub(crate) dropped: u64,
    pub(crate) aborted: u64,
    pub(crate) completed: u64,
    pub(crate) ok: u64,
    pub(crate) http_fail: u64,
    pub(crate) transport_err: u64,
    pub(crate) timeout_err: u64,
    pub(crate) cancelled: u64,
    pub(crate) worker_error: u64,
    pub(crate) in_flight: u64,
    pub(crate) max_in_flight_seen: u64,
    pub(crate) codes: [u64; 600],
    pub(crate) latency: Histogram,
    pub(crate) queue_wait: Histogram,
    pub(crate) preparation: Histogram,
    pub(crate) buckets: Vec<TimeBucket>,
    pub(crate) drain_duration: Duration,
    pub(crate) run_origin: Instant,
    pub(crate) measurement_start: Instant,
    pub(crate) measurement_end: Instant,
    pub(crate) measurement_in_flight_end: Option<u64>,
    measurement_in_flight_snapshot_at: Option<Instant>,
    pub(crate) resource_start: ResourceSample,
    pub(crate) resource_end: ResourceSample,
    planned_duration: Duration,
    pub(crate) stop_reason: &'static str,
}

impl Stats {
    pub(crate) fn new(start: Instant, duration: Duration) -> Self {
        Self::new_with_origin(start, start, start + duration, duration)
    }

    pub(crate) fn new_with_origin(
        run_origin: Instant,
        measurement_start: Instant,
        measurement_end: Instant,
        duration: Duration,
    ) -> Self {
        let window_count = duration.as_nanos().div_ceil(NANOS_PER_SECOND).min(86_400) as usize;
        let buckets = (0..window_count)
            .map(|index| {
                let start_ns = index as u64 * NANOS_PER_SECOND as u64;
                let end_ns = (start_ns + NANOS_PER_SECOND as u64)
                    .min(duration.as_nanos().min(u64::MAX as u128) as u64);
                TimeBucket::new(start_ns, end_ns)
            })
            .collect();
        Self {
            scheduled: 0,
            started: 0,
            missed: 0,
            dropped: 0,
            aborted: 0,
            completed: 0,
            ok: 0,
            http_fail: 0,
            transport_err: 0,
            timeout_err: 0,
            cancelled: 0,
            worker_error: 0,
            in_flight: 0,
            max_in_flight_seen: 0,
            codes: [0; 600],
            latency: Histogram::new(),
            queue_wait: Histogram::new(),
            preparation: Histogram::new(),
            buckets,
            drain_duration: Duration::ZERO,
            run_origin,
            measurement_start,
            measurement_end,
            measurement_in_flight_end: None,
            measurement_in_flight_snapshot_at: None,
            resource_start: ResourceSample::default(),
            resource_end: ResourceSample::default(),
            planned_duration: duration,
            stop_reason: "normal",
        }
    }

    pub(crate) fn measurement_duration(&self) -> Duration {
        self.measurement_end
            .saturating_duration_since(self.measurement_start)
    }

    fn in_measurement_window(&self, at: Instant) -> bool {
        if at < self.measurement_start {
            return false;
        }
        if self.measurement_end > self.measurement_start {
            at < self.measurement_end
        } else if self.planned_duration.is_zero() {
            true
        } else {
            at.duration_since(self.measurement_start) < self.planned_duration
        }
    }

    fn bucket_index(&self, at: Instant) -> Option<usize> {
        if self.buckets.is_empty() || !self.in_measurement_window(at) {
            return None;
        }
        let index =
            (at.duration_since(self.measurement_start).as_nanos() / NANOS_PER_SECOND) as usize;
        (index < self.buckets.len()).then_some(index)
    }

    fn range_bucket_count(rate: f64, bucket: &TimeBucket, first: u64, end: u64) -> u64 {
        let start_seconds = bucket.start_ns as f64 / NANOS_PER_SECOND as f64;
        let end_seconds = bucket.end_ns as f64 / NANOS_PER_SECOND as f64;
        let first_in_bucket = (rate * start_seconds).ceil() as u64;
        let end_in_bucket = (rate * end_seconds).ceil() as u64;
        end.min(end_in_bucket)
            .saturating_sub(first.max(first_in_bucket))
    }

    pub(crate) fn record_open_loop_slots(
        &mut self,
        rate: f64,
        first: u64,
        end: u64,
        missed_end: u64,
    ) {
        if first >= end {
            return;
        }
        let missed_end = missed_end.min(end);
        let scheduled = end - first;
        let missed = missed_end.saturating_sub(first);
        self.scheduled = self.scheduled.saturating_add(scheduled);
        self.missed = self.missed.saturating_add(missed);
        let measurement_window_ns = if self.measurement_end == self.measurement_start {
            self.planned_duration.as_nanos()
        } else {
            self.measurement_duration().as_nanos()
        };
        for bucket in &mut self.buckets {
            let active_measurement_bucket = (bucket.start_ns as u128) < measurement_window_ns;
            if !active_measurement_bucket {
                continue;
            }
            let scheduled = Self::range_bucket_count(rate, bucket, first, end);
            let missed = Self::range_bucket_count(rate, bucket, first, missed_end);
            bucket.scheduled = bucket.scheduled.saturating_add(scheduled);
            bucket.missed = bucket.missed.saturating_add(missed);
        }
    }

    pub(crate) fn record_aborted_slots(&mut self, rate: f64, first: u64, end: u64) {
        if first >= end {
            return;
        }
        let count = end - first;
        self.scheduled = self.scheduled.saturating_add(count);
        self.aborted = self.aborted.saturating_add(count);
        let measurement_window_ns = if self.measurement_end == self.measurement_start {
            self.planned_duration.as_nanos()
        } else {
            self.measurement_duration().as_nanos()
        };
        for bucket in &mut self.buckets {
            if bucket.start_ns as u128 >= measurement_window_ns {
                continue;
            }
            let aborted = Self::range_bucket_count(rate, bucket, first, end);
            bucket.scheduled = bucket.scheduled.saturating_add(aborted);
            bucket.aborted = bucket.aborted.saturating_add(aborted);
        }
    }

    pub(crate) fn record_dropped_slot(&mut self, due_at: Instant) {
        self.dropped = self.dropped.saturating_add(1);
        if let Some(index) = self.bucket_index(due_at) {
            self.buckets[index].dropped = self.buckets[index].dropped.saturating_add(1);
        }
    }

    pub(crate) fn record_started(&mut self, due_at: Instant) {
        self.started = self.started.saturating_add(1);
        self.in_flight = self.in_flight.saturating_add(1);
        self.max_in_flight_seen = self.max_in_flight_seen.max(self.in_flight);
        if let Some(index) = self.bucket_index(due_at) {
            self.buckets[index].started = self.buckets[index].started.saturating_add(1);
        }
    }

    pub(crate) fn capture_measurement_in_flight(&mut self, snapshot_at: Instant, active: u64) {
        self.measurement_in_flight_end = Some(active);
        self.measurement_in_flight_snapshot_at = Some(snapshot_at);
    }

    pub(crate) fn measurement_in_flight_offset_ns(&self) -> Option<i128> {
        let sampled_at = self.measurement_in_flight_snapshot_at?;
        if sampled_at >= self.measurement_end {
            i128::try_from(sampled_at.duration_since(self.measurement_end).as_nanos()).ok()
        } else {
            i128::try_from(self.measurement_end.duration_since(sampled_at).as_nanos())
                .ok()
                .map(|offset| -offset)
        }
    }

    pub(crate) fn measurement_in_flight_snapshot_at(&self) -> Option<Instant> {
        self.measurement_in_flight_snapshot_at
    }

    pub(crate) fn measurement_in_flight_snapshot_is_reliable(&self) -> bool {
        self.measurement_in_flight_offset_ns()
            .is_some_and(|offset| (0..=1_000_000).contains(&offset))
    }

    pub(crate) fn measurement_start_offset_ns(&self) -> Option<u128> {
        (self.measurement_start >= self.run_origin).then(|| {
            self.measurement_start
                .duration_since(self.run_origin)
                .as_nanos()
        })
    }

    pub(crate) fn measurement_end_offset_ns(&self) -> Option<u128> {
        (self.measurement_end >= self.run_origin).then(|| {
            self.measurement_end
                .duration_since(self.run_origin)
                .as_nanos()
        })
    }

    pub(crate) fn measurement_end_unix_ms(&self, run_started_at_unix_ms: u128) -> Option<u128> {
        let elapsed = self
            .measurement_end
            .duration_since(self.run_origin)
            .as_nanos();
        Some(run_started_at_unix_ms.saturating_add(elapsed / 1_000_000))
    }

    pub(crate) fn measurement_in_flight_snapshot_offset_ns(&self) -> Option<i128> {
        let snapshot = self.measurement_in_flight_snapshot_at?;
        if snapshot >= self.run_origin {
            i128::try_from(snapshot.duration_since(self.run_origin).as_nanos()).ok()
        } else {
            i128::try_from(self.run_origin.duration_since(snapshot).as_nanos())
                .ok()
                .map(|offset| -offset)
        }
    }

    pub(crate) fn window_successes(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0u64, |total, bucket| total.saturating_add(bucket.ok))
    }

    pub(crate) fn request_failures(&self) -> u64 {
        self.http_fail
            .saturating_add(self.transport_err)
            .saturating_add(self.timeout_err)
            .saturating_add(self.worker_error)
    }

    pub(crate) fn measurement_cohort_started(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0u64, |total, bucket| total.saturating_add(bucket.started))
    }

    pub(crate) fn measurement_cohort_successes(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0u64, |total, bucket| total.saturating_add(bucket.cohort_ok))
    }

    #[cfg(test)]
    pub(crate) fn measurement_cohort_completed_for_window(&self, index: usize) -> Option<u64> {
        self.buckets
            .get(index)
            .map(|bucket| bucket.cohort_completed)
    }

    pub(crate) fn measurement_cohort_failures(&self) -> u64 {
        self.buckets.iter().fold(0u64, |total, bucket| {
            total.saturating_add(bucket.cohort_failures)
        })
    }

    pub(crate) fn measurement_cohort_worker_errors(&self) -> u64 {
        self.buckets.iter().fold(0u64, |total, bucket| {
            total.saturating_add(bucket.cohort_worker_errors)
        })
    }

    pub(crate) fn measurement_cohort_cancelled(&self) -> u64 {
        self.buckets.iter().fold(0u64, |total, bucket| {
            total.saturating_add(bucket.cohort_cancelled)
        })
    }

    pub(crate) fn measurement_cohort_error_count(&self) -> u64 {
        self.measurement_cohort_failures()
    }

    pub(crate) fn measurement_cohort_error_rate(&self) -> Option<f64> {
        let started = self.measurement_cohort_started();
        (started > 0
            && self.cohort_results_accounted()
            && self.measurement_cohort_cancelled() == 0
            && self.measurement_cohort_worker_errors() == 0)
            .then(|| self.measurement_cohort_error_count() as f64 / started as f64)
    }

    pub(crate) fn measurement_cohort_error_rate_ci95(&self) -> Option<(f64, f64)> {
        if !self.cohort_results_accounted()
            || self.measurement_cohort_cancelled() > 0
            || self.measurement_cohort_worker_errors() > 0
        {
            return None;
        }
        wilson_interval_95(
            self.measurement_cohort_error_count(),
            self.measurement_cohort_started(),
        )
    }

    pub(crate) fn measurement_cohort_results_accounted(&self) -> bool {
        self.cohort_results_accounted()
    }

    pub(crate) fn measurement_cohort_latency_results_complete(&self) -> bool {
        self.cohort_results_accounted()
            && self.measurement_cohort_cancelled() == 0
            && self.measurement_cohort_worker_errors() == 0
            && self.measurement_cohort_started() == self.latency.count()
    }

    fn cohort_results_accounted(&self) -> bool {
        let started = self.measurement_cohort_started();
        let completed = self.buckets.iter().fold(0u64, |total, bucket| {
            total.saturating_add(bucket.cohort_completed)
        });
        let cancelled = self.buckets.iter().fold(0u64, |total, bucket| {
            total.saturating_add(bucket.cohort_cancelled)
        });
        let completed_results = self.buckets.iter().all(|bucket| {
            bucket.cohort_completed
                == bucket
                    .cohort_ok
                    .saturating_add(bucket.cohort_failures)
                    .saturating_add(bucket.cohort_worker_errors)
        });
        completed_results && started == completed.saturating_add(cancelled)
    }

    fn request_results_accounted(&self) -> bool {
        self.started
            == self
                .completed
                .saturating_add(self.cancelled)
                .saturating_add(self.in_flight)
            && self.completed
                == self
                    .ok
                    .saturating_add(self.http_fail)
                    .saturating_add(self.transport_err)
                    .saturating_add(self.timeout_err)
                    .saturating_add(self.worker_error)
    }

    pub(crate) fn set_resource_sample(
        &mut self,
        boundary: MeasurementBoundary,
        sample: ResourceSample,
    ) {
        match boundary {
            MeasurementBoundary::Start => self.resource_start = sample,
            MeasurementBoundary::End => self.resource_end = sample,
        }
    }

    pub(crate) fn record_completion(&mut self, sample: RequestSample) {
        self.completed = self.completed.saturating_add(1);
        self.in_flight = self.in_flight.saturating_sub(1);
        let measured_request = self.in_measurement_window(sample.due_at);
        self.record_latency_sample(sample, measured_request);
        if measured_request {
            let index = (sample
                .due_at
                .duration_since(self.measurement_start)
                .as_nanos()
                / NANOS_PER_SECOND) as usize;
            if let Some(bucket) = self.buckets.get_mut(index) {
                bucket.cohort_completed = bucket.cohort_completed.saturating_add(1);
                match sample.outcome {
                    RequestOutcome::Http(code) if (200..300).contains(&code) => {
                        bucket.cohort_ok = bucket.cohort_ok.saturating_add(1);
                    }
                    _ => bucket.cohort_failures = bucket.cohort_failures.saturating_add(1),
                }
            }
        }
        if let Some(index) = self.bucket_index(sample.completed_at) {
            let bucket = &mut self.buckets[index];
            bucket.completed = bucket.completed.saturating_add(1);
            match sample.outcome {
                RequestOutcome::Http(code) if (200..300).contains(&code) => {
                    bucket.ok = bucket.ok.saturating_add(1);
                }
                RequestOutcome::Http(_) => {
                    bucket.http_fail = bucket.http_fail.saturating_add(1);
                }
                RequestOutcome::Transport => {
                    bucket.transport_err = bucket.transport_err.saturating_add(1);
                }
                RequestOutcome::Timeout => {
                    bucket.timeout_err = bucket.timeout_err.saturating_add(1);
                }
            }
        }
        match sample.outcome {
            RequestOutcome::Http(code) => {
                let index = (code as usize).min(self.codes.len() - 1);
                self.codes[index] = self.codes[index].saturating_add(1);
                if (200..300).contains(&code) {
                    self.ok = self.ok.saturating_add(1);
                } else {
                    self.http_fail = self.http_fail.saturating_add(1);
                }
            }
            RequestOutcome::Transport => {
                self.transport_err = self.transport_err.saturating_add(1);
            }
            RequestOutcome::Timeout => {
                self.timeout_err = self.timeout_err.saturating_add(1);
            }
        }
    }

    fn record_latency_sample(&mut self, sample: RequestSample, measured_request: bool) {
        let queue_wait_ns = sample
            .task_started_at
            .saturating_duration_since(sample.due_at)
            .as_nanos() as u64;
        let preparation_ns = sample
            .request_started_at
            .saturating_duration_since(sample.task_started_at)
            .as_nanos() as u64;
        let latency_ns = sample
            .completed_at
            .saturating_duration_since(sample.request_started_at)
            .as_nanos() as u64;
        if measured_request {
            self.latency.record(latency_ns);
            self.queue_wait.record(queue_wait_ns);
            self.preparation.record(preparation_ns);
        }
    }

    fn record_cancelled(&mut self, due_at: Option<Instant>) {
        self.cancelled = self.cancelled.saturating_add(1);
        self.in_flight = self.in_flight.saturating_sub(1);
        if let Some(due_at) = due_at.filter(|due_at| self.in_measurement_window(*due_at)) {
            let index = (due_at.duration_since(self.measurement_start).as_nanos()
                / NANOS_PER_SECOND) as usize;
            if let Some(bucket) = self.buckets.get_mut(index) {
                bucket.cohort_cancelled = bucket.cohort_cancelled.saturating_add(1);
            }
        }
    }

    fn record_worker_error(&mut self, at: Instant, due_at: Option<Instant>) {
        self.completed = self.completed.saturating_add(1);
        self.worker_error = self.worker_error.saturating_add(1);
        self.in_flight = self.in_flight.saturating_sub(1);
        if let Some(due_at) = due_at.filter(|due_at| self.in_measurement_window(*due_at)) {
            let index = (due_at.duration_since(self.measurement_start).as_nanos()
                / NANOS_PER_SECOND) as usize;
            if let Some(bucket) = self.buckets.get_mut(index) {
                bucket.cohort_completed = bucket.cohort_completed.saturating_add(1);
                bucket.cohort_worker_errors = bucket.cohort_worker_errors.saturating_add(1);
            }
        }
        if let Some(index) = self.bucket_index(at) {
            let bucket = &mut self.buckets[index];
            bucket.completed = bucket.completed.saturating_add(1);
            bucket.worker_error = bucket.worker_error.saturating_add(1);
        }
    }

    pub(crate) fn finalize_windows(&mut self) {
        let window_seconds = self.measurement_duration().as_secs_f64();
        let active_buckets = self
            .buckets
            .iter()
            .take_while(|bucket| {
                bucket.start_ns as f64 / (NANOS_PER_SECOND as f64) < window_seconds
            })
            .count();
        let mut in_flight = 0i64;
        for bucket in self.buckets.iter_mut().take(active_buckets) {
            in_flight = in_flight
                .saturating_add(bucket.started as i64)
                .saturating_sub(bucket.completed as i64);
            bucket.in_flight_end = in_flight;
        }
    }

    pub(crate) fn failures(&self) -> u64 {
        self.request_failures().saturating_add(self.cancelled)
    }

    pub(crate) fn loadgen_underrun_count(&self) -> u64 {
        self.missed
            .saturating_add(self.dropped)
            .saturating_add(self.aborted)
    }

    pub(crate) fn loadgen_underrun_rate(&self) -> Option<f64> {
        (self.scheduled > 0).then(|| self.loadgen_underrun_count() as f64 / self.scheduled as f64)
    }

    pub(crate) fn request_error_rate(&self) -> Option<f64> {
        (self.request_results_complete() && self.started > 0)
            .then(|| self.request_failures() as f64 / self.started as f64)
    }

    pub(crate) fn loadgen_underrun_rate_ci95(&self) -> Option<(f64, f64)> {
        wilson_interval_95(self.loadgen_underrun_count(), self.scheduled)
    }

    pub(crate) fn request_error_rate_ci95(&self) -> Option<(f64, f64)> {
        self.request_results_complete()
            .then(|| wilson_interval_95(self.request_failures(), self.started))
            .flatten()
    }

    pub(crate) fn request_results_complete(&self) -> bool {
        self.in_flight == 0 && self.cancelled == 0 && self.request_results_accounted()
    }

    pub(crate) fn request_latency_results_complete(&self) -> bool {
        self.request_results_complete() && self.latency.count() == self.started
    }

    pub(crate) fn client_in_flight_slope_per_second(&self) -> Option<f64> {
        if self.measurement_end <= self.measurement_start {
            return None;
        }
        let measurement_seconds = self.measurement_duration().as_secs_f64();
        let active_buckets = self
            .buckets
            .iter()
            .take_while(|bucket| {
                bucket.start_ns as f64 / (NANOS_PER_SECOND as f64) < measurement_seconds
            })
            .count();
        if active_buckets < 3 || self.measurement_in_flight_end.is_none() {
            return None;
        }
        let points = self
            .buckets
            .iter()
            .take(active_buckets)
            .map(|bucket| {
                (
                    (bucket.start_ns + bucket.end_ns) as f64 / 2.0 / NANOS_PER_SECOND as f64,
                    bucket.in_flight_end as f64,
                )
            })
            .collect::<Vec<_>>();
        let mean_x = points.iter().map(|(x, _)| *x).sum::<f64>() / points.len() as f64;
        let mean_y = points.iter().map(|(_, y)| *y).sum::<f64>() / points.len() as f64;
        let numerator = points
            .iter()
            .map(|(x, y)| (x - mean_x) * (y - mean_y))
            .sum::<f64>();
        let denominator = points
            .iter()
            .map(|(x, _)| (x - mean_x).powi(2))
            .sum::<f64>();
        (denominator > 0.0).then_some(numerator / denominator)
    }

    pub(crate) fn accounting_ok(&self) -> bool {
        self.scheduled
            == self
                .started
                .saturating_add(self.missed)
                .saturating_add(self.dropped)
                .saturating_add(self.aborted)
            && self.started
                == self
                    .completed
                    .saturating_add(self.cancelled)
                    .saturating_add(self.in_flight)
            && self.completed
                == self
                    .ok
                    .saturating_add(self.http_fail)
                    .saturating_add(self.transport_err)
                    .saturating_add(self.timeout_err)
                    .saturating_add(self.worker_error)
    }
}

fn wilson_interval_95(errors: u64, total: u64) -> Option<(f64, f64)> {
    if total == 0 || errors > total {
        return None;
    }
    let n = total as f64;
    let p = errors as f64 / n;
    let z = 1.959_963_984_540_054;
    let z2 = z * z;
    let denominator = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denominator;
    let half = z * ((p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt()) / denominator;
    Some(((center - half).max(0.0), (center + half).min(1.0)))
}

fn record_join(stats: &mut Stats, joined: TrackedJoin<RequestSample>) {
    match joined {
        TrackedJoin::Output(sample) => stats.record_completion(sample),
        TrackedJoin::JoinError { due_at, error } if error.is_cancelled() => {
            stats.record_cancelled(due_at)
        }
        TrackedJoin::JoinError { due_at, .. } => stats.record_worker_error(Instant::now(), due_at),
    }
}

fn spawn_request<F, Fut>(
    tasks: &mut TrackedTasks<RequestSample>,
    request: &F,
    due: Instant,
    sequence: u64,
) where
    F: Fn(Instant, u64) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = RequestSample> + Send + 'static,
{
    let request = request.clone();
    tasks.spawn(async move { request(due, sequence).await }, due);
}

async fn drain(tasks: &mut TrackedTasks<RequestSample>, stats: &mut Stats, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, tasks.join_next()).await {
            Ok(Some(joined)) => record_join(stats, joined),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if !tasks.is_empty() {
        tasks.abort_all();
    }
    while let Some(joined) = tasks.join_next().await {
        record_join(stats, joined);
    }
}

fn error_limit_reached(stats: &Stats, enabled: bool, max_errors: u64) -> bool {
    enabled && max_errors > 0 && stats.failures() >= max_errors
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_open_loop<F, Fut, B>(
    request: F,
    start: Instant,
    rate: f64,
    duration: Duration,
    max_in_flight: usize,
    drain_timeout: Duration,
    stop_at_error_limit: bool,
    max_errors: u64,
    mut on_measurement_boundary: B,
) -> Stats
where
    F: Fn(Instant, u64) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = RequestSample> + Send + 'static,
    B: FnMut(MeasurementBoundary, Instant) -> ResourceSample,
{
    let requested_start = start.max(Instant::now());
    let start_sample = on_measurement_boundary(MeasurementBoundary::Start, requested_start);
    let measurement_start = start_sample.sampled_at.unwrap_or(requested_start);
    let deadline = measurement_start + duration;

    let total_slots = (rate * duration.as_secs_f64()).ceil() as u64;
    let mut stats = Stats::new_with_origin(start, measurement_start, deadline, duration);
    stats.set_resource_sample(MeasurementBoundary::Start, start_sample);
    let mut next_slot = 0u64;
    let mut tasks = TrackedTasks::new();
    while next_slot < total_slots {
        if error_limit_reached(&stats, stop_at_error_limit, max_errors) {
            stats.stop_reason = "error_limit";
            stats.record_aborted_slots(rate, next_slot, total_slots);
            break;
        }
        let due = measurement_start + Duration::from_secs_f64(next_slot as f64 / rate);
        let wait = due.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            while let Some(joined) = tasks.try_join_next() {
                record_join(&mut stats, joined);
                if error_limit_reached(&stats, stop_at_error_limit, max_errors) {
                    break;
                }
            }
        } else if !tasks.is_empty() {
            if let Ok(Some(joined)) = tokio::time::timeout(wait, tasks.join_next()).await {
                record_join(&mut stats, joined);
                continue;
            }
        } else {
            tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
        }

        if error_limit_reached(&stats, stop_at_error_limit, max_errors) {
            stats.stop_reason = "error_limit";
            stats.record_aborted_slots(rate, next_slot, total_slots);
            break;
        }

        let now = Instant::now();
        if now >= deadline {
            stats.record_open_loop_slots(rate, next_slot, total_slots, total_slots);
            break;
        }

        let elapsed_slots =
            (now.duration_since(measurement_start).as_secs_f64() * rate).floor() as u64;
        let due_slot = elapsed_slots.max(next_slot).min(total_slots - 1);
        stats.record_open_loop_slots(rate, next_slot, due_slot + 1, due_slot);
        let due_at = measurement_start + Duration::from_secs_f64(due_slot as f64 / rate);
        if tasks.len() >= max_in_flight {
            stats.record_dropped_slot(due_at);
        } else {
            stats.record_started(due_at);
            spawn_request(&mut tasks, &request, due_at, due_slot);
        }
        next_slot = due_slot + 1;
    }

    if stats.stop_reason == "normal" {
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if tasks.is_empty() {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                break;
            }
            match tokio::time::timeout(remaining, tasks.join_next()).await {
                Ok(Some(joined)) => {
                    record_join(&mut stats, joined);
                    if error_limit_reached(&stats, stop_at_error_limit, max_errors) {
                        stats.stop_reason = "error_limit";
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
    stats.measurement_end = if stats.stop_reason == "normal" {
        deadline
    } else {
        Instant::now().min(deadline)
    };
    let end_boundary_requested_at = if stats.stop_reason == "normal" {
        stats.measurement_end
    } else {
        Instant::now()
    };
    let in_flight_snapshot_at = Instant::now();
    stats.capture_measurement_in_flight(in_flight_snapshot_at, tasks.active_count());
    let end_sample = on_measurement_boundary(MeasurementBoundary::End, end_boundary_requested_at);
    stats.set_resource_sample(MeasurementBoundary::End, end_sample);
    let drain_started = Instant::now();
    drain(&mut tasks, &mut stats, drain_timeout).await;
    stats.drain_duration = drain_started.elapsed();
    stats.finalize_windows();
    stats
}

pub(crate) async fn run_closed_loop<F, Fut>(
    request: F,
    start: Instant,
    concurrency: usize,
    duration: Duration,
    drain_timeout: Duration,
) -> Stats
where
    F: Fn(Instant, u64) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = RequestSample> + Send + 'static,
{
    let deadline = start + duration;
    let mut stats = Stats::new(start, duration);
    let mut tasks = TrackedTasks::new();
    let mut sequence = 0u64;
    for _ in 0..concurrency {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        stats.scheduled = stats.scheduled.saturating_add(1);
        stats.record_started(now);
        spawn_request(&mut tasks, &request, now, sequence);
        sequence += 1;
    }
    while !tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, tasks.join_next()).await {
            Ok(Some(joined)) => {
                record_join(&mut stats, joined);
                let now = Instant::now();
                if now < deadline {
                    stats.scheduled = stats.scheduled.saturating_add(1);
                    stats.record_started(now);
                    spawn_request(&mut tasks, &request, now, sequence);
                    sequence += 1;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    stats.measurement_end = deadline;
    let drain_started = Instant::now();
    drain(&mut tasks, &mut stats, drain_timeout).await;
    stats.drain_duration = drain_started.elapsed();
    stats.finalize_windows();
    stats
}

pub(crate) async fn run_count<F, Fut>(
    request: F,
    start: Instant,
    concurrency: usize,
    count: u64,
) -> Stats
where
    F: Fn(Instant, u64) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = RequestSample> + Send + 'static,
{
    let mut stats = Stats::new(start, Duration::ZERO);
    stats.scheduled = count;
    let mut tasks = TrackedTasks::new();
    let mut next_sequence = 0u64;
    while next_sequence < count && tasks.len() < concurrency {
        let now = Instant::now();
        stats.record_started(now);
        spawn_request(&mut tasks, &request, now, next_sequence);
        next_sequence += 1;
    }
    while let Some(joined) = tasks.join_next().await {
        record_join(&mut stats, joined);
        if next_sequence < count {
            let now = Instant::now();
            stats.record_started(now);
            spawn_request(&mut tasks, &request, now, next_sequence);
            next_sequence += 1;
        }
    }
    stats.measurement_end = Instant::now();
    stats.finalize_windows();
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(due: Instant, duration: Duration, outcome: RequestOutcome) -> RequestSample {
        let task_started = Instant::now();
        RequestSample::new(
            outcome,
            due,
            task_started,
            task_started,
            task_started + duration,
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn histogram_tracks_quantiles_and_conservative_confidence_bounds() {
        let mut histogram = Histogram::new();
        for value in [100, 200, 10_000, 10_100, 20_000] {
            histogram.record(value);
        }
        assert_eq!(histogram.count(), 5);
        assert_eq!(histogram.mean_ns(), Some(8_080));
        assert_eq!(histogram.percentile_ns(50.0), Some(10_000));
        assert_eq!(histogram.percentile_ci95_ns(99.0).unwrap().1, 20_000);
        assert_eq!(histogram.max_ns(), Some(20_000));
        assert_eq!(histogram.nonempty_buckets().map(|(_, n)| n).sum::<u64>(), 5);
    }

    #[test]
    fn slot_accounting_counts_missed_dropped_and_aborted_separately() {
        let start = Instant::now();
        let mut stats = Stats::new(start, Duration::from_secs(2));
        stats.record_open_loop_slots(10.0, 0, 7, 5);
        stats.record_started(start);
        stats.record_dropped_slot(start + Duration::from_millis(500));
        stats.record_aborted_slots(10.0, 7, 10);
        assert_eq!(stats.scheduled, 10);
        assert_eq!(stats.missed, 5);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.aborted, 3);
        assert_eq!(stats.buckets[0].scheduled, 10);
        assert_eq!(stats.buckets[0].missed, 5);
        assert_eq!(stats.buckets[0].dropped, 1);
        assert_eq!(stats.buckets[0].aborted, 3);
        assert_eq!(stats.started, 1);
        assert!(stats.accounting_ok());
    }

    #[test]
    fn accounting_separates_http_timeout_and_transport_failures() {
        let now = Instant::now();
        let mut stats = Stats::new(now, Duration::from_secs(2));
        for outcome in [
            RequestOutcome::Http(200),
            RequestOutcome::Http(503),
            RequestOutcome::Transport,
            RequestOutcome::Timeout,
        ] {
            stats.scheduled += 1;
            stats.record_started(now);
            stats.record_completion(sample(now, Duration::from_nanos(100), outcome));
        }
        stats.finalize_windows();
        assert_eq!(stats.ok, 1);
        assert_eq!(stats.http_fail, 1);
        assert_eq!(stats.transport_err, 1);
        assert_eq!(stats.timeout_err, 1);
        assert_eq!(stats.failures(), 3);
        assert!(stats.accounting_ok());
    }

    #[test]
    fn open_loop_is_bounded_and_preserves_slot_accounting() {
        runtime().block_on(async {
            let start = Instant::now();
            let delay = Duration::from_millis(8);
            let stats = run_open_loop(
                move |due, _sequence| async move {
                    tokio::time::sleep(delay).await;
                    sample(due, delay, RequestOutcome::Http(200))
                },
                start,
                500.0,
                Duration::from_millis(40),
                2,
                Duration::from_millis(100),
                false,
                0,
                |_, _| ResourceSample::default(),
            )
            .await;
            assert_eq!(stats.scheduled, 20);
            assert_eq!(
                stats.scheduled,
                stats.started + stats.missed + stats.dropped + stats.aborted
            );
            assert_eq!(
                stats.started,
                stats.completed + stats.cancelled + stats.in_flight
            );
            assert!(stats.dropped > 0);
            assert!(stats.max_in_flight_seen <= 2);
            assert_eq!(stats.in_flight, 0);
            assert!(stats.accounting_ok());
            assert_eq!(stats.buckets.len(), 1);
        });
    }

    #[test]
    fn high_offered_rate_fake_sink_is_bounded_and_separates_measurement_from_drain() {
        runtime().block_on(async {
            let wall_start = Instant::now();
            let start = Instant::now();
            let duration = Duration::from_millis(10);
            let stats = tokio::time::timeout(
                Duration::from_secs(2),
                run_open_loop(
                    |due, _sequence| async move {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        let task_started = Instant::now();
                        let preparation = Duration::from_millis(1);
                        tokio::time::sleep(preparation + Duration::from_millis(15)).await;
                        RequestSample::new(
                            RequestOutcome::Http(200),
                            due,
                            task_started,
                            task_started + preparation,
                            Instant::now(),
                        )
                    },
                    start,
                    1_000.0,
                    duration,
                    1,
                    Duration::from_millis(100),
                    false,
                    0,
                    |_, _| ResourceSample::default(),
                ),
            )
            .await
            .expect("fake-sink pacing must finish within the wall-clock bound");
            let wall_duration = wall_start.elapsed();

            assert!(wall_duration < Duration::from_secs(2));
            assert_eq!(stats.measurement_duration(), duration);
            assert!(stats.measurement_end < Instant::now());
            assert!(stats.drain_duration >= Duration::from_millis(1));
            assert!(
                stats
                    .measurement_in_flight_end
                    .expect("measurement in-flight snapshot")
                    > 0
            );
            assert!(
                stats.dropped > 0,
                "overloaded arrival slots must be recorded as dropped"
            );
            assert_eq!(stats.max_in_flight_seen, 1);
            assert!(stats.queue_wait.mean_ns().unwrap() > 0);
            assert!(stats.preparation.mean_ns().unwrap() > 0);
            assert!(stats.latency.mean_ns().unwrap() > 0);
            assert!(stats.queue_wait.mean_ns().unwrap() < stats.latency.mean_ns().unwrap());
            assert!(stats.preparation.mean_ns().unwrap() < stats.latency.mean_ns().unwrap());
            assert_eq!(
                stats.scheduled,
                stats.started + stats.missed + stats.dropped + stats.aborted
            );
            assert_eq!(
                stats.started,
                stats.completed + stats.cancelled + stats.in_flight
            );
            assert!(stats.accounting_ok());
            assert_eq!(stats.in_flight, 0);
            assert_eq!(stats.measurement_cohort_started(), 1);
            assert_eq!(stats.measurement_cohort_successes(), 1);
            assert_eq!(stats.measurement_cohort_completed_for_window(0), Some(1));
            assert_eq!(stats.window_successes(), 0);
            assert!(stats.measurement_cohort_latency_results_complete());
        });
    }

    #[test]
    fn open_loop_stops_at_error_limit_and_records_unoffered_slots() {
        runtime().block_on(async {
            let start = Instant::now();
            let stats = run_open_loop(
                |due, _sequence| async move {
                    sample(due, Duration::from_millis(1), RequestOutcome::Http(503))
                },
                start,
                100.0,
                Duration::from_secs(1),
                2,
                Duration::from_millis(100),
                true,
                1,
                |_, _| ResourceSample::default(),
            )
            .await;
            assert_eq!(stats.stop_reason, "error_limit");
            assert!(stats.aborted > 0);
            assert!(stats.accounting_ok());
        });
    }

    #[test]
    fn drain_timeout_cancels_remaining_requests() {
        runtime().block_on(async {
            let start = Instant::now();
            let stats = run_open_loop(
                |due, _sequence| async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    sample(due, Duration::from_secs(1), RequestOutcome::Http(200))
                },
                start,
                100.0,
                Duration::from_millis(10),
                1,
                Duration::from_millis(5),
                false,
                0,
                |_, _| ResourceSample::default(),
            )
            .await;
            assert_eq!(stats.started, 1);
            assert_eq!(stats.cancelled, 1);
            assert_eq!(stats.measurement_cohort_cancelled(), 1);
            assert_eq!(stats.in_flight, 0);
            assert!(!stats.measurement_cohort_error_rate_ci95().is_some());
            assert!(!stats.measurement_cohort_latency_results_complete());
            assert!(!stats.request_results_complete());
            assert!(stats.accounting_ok());
        });
    }

    #[test]
    fn panicked_cohort_worker_is_accounted_but_cannot_pass_latency_or_error_slo() {
        runtime().block_on(async {
            let stats = run_open_loop(
                |_due, _sequence| async move { panic!("fake worker panic") },
                Instant::now(),
                20.0,
                Duration::from_millis(50),
                1,
                Duration::from_millis(20),
                false,
                0,
                |_, _| ResourceSample::default(),
            )
            .await;

            assert_eq!(stats.measurement_cohort_worker_errors(), 1);
            assert!(stats.measurement_cohort_results_accounted());
            assert!(!stats.measurement_cohort_latency_results_complete());
            assert_eq!(stats.measurement_cohort_error_rate(), None);
            assert_eq!(stats.measurement_cohort_error_rate_ci95(), None);
            assert!(stats.accounting_ok());
        });
    }

    #[test]
    fn in_flight_snapshot_reliability_uses_the_measurement_end_tolerance() {
        let origin = Instant::now();
        let measurement_start = origin + Duration::from_millis(1);
        let measurement_end = measurement_start + Duration::from_millis(10);
        let mut stats = Stats::new_with_origin(
            origin,
            measurement_start,
            measurement_end,
            Duration::from_millis(10),
        );

        stats.capture_measurement_in_flight(measurement_end, 3);
        assert_eq!(stats.measurement_in_flight_offset_ns(), Some(0));
        assert!(stats.measurement_in_flight_snapshot_is_reliable());
        assert_eq!(stats.measurement_in_flight_end, Some(3));

        stats.capture_measurement_in_flight(measurement_end - Duration::from_nanos(1), 2);
        assert_eq!(stats.measurement_in_flight_offset_ns(), Some(-1));
        assert!(!stats.measurement_in_flight_snapshot_is_reliable());

        stats.capture_measurement_in_flight(measurement_end + Duration::from_millis(1), 1);
        assert_eq!(stats.measurement_in_flight_offset_ns(), Some(1_000_000));
        assert!(stats.measurement_in_flight_snapshot_is_reliable());

        stats.capture_measurement_in_flight(
            measurement_end + Duration::from_millis(1) + Duration::from_nanos(1),
            0,
        );
        assert!(!stats.measurement_in_flight_snapshot_is_reliable());
        assert!(stats.measurement_in_flight_snapshot_offset_ns().is_some());
    }
}
