//! Compact publication notifications fence reads without installing authorization.

use astral_types::{PublicationStamp, PublishedEvidenceAggregate};

use super::{
    CompletionIdentity, MemoryProjectionHub, PendingDeltaEntry, ProjectionAggregateIdentity,
    MAX_MIRROR_STATES, MIRROR_TTL,
};

#[derive(Debug, Clone)]
pub struct EvidenceInvalidationRequest {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: PublishedEvidenceAggregate,
    pub aggregate_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub source_generation: u64,
    pub revoke_fence: u64,
    /// The observed baseline is not proof that this source mutation was published.
    pub published_generation: u64,
    pub stamp: PublicationStamp,
}

impl MemoryProjectionHub {
    /// Highest applied notification generation; never an installed-state proof.
    #[must_use]
    pub fn applied_generation_watermark(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Option<u64> {
        self.applied_publication_stamp(identity)
            .map(|stamp| stamp.generation)
    }

    /// Full identity of the highest applied notification; never an installed-state proof.
    #[must_use]
    pub fn applied_publication_stamp(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Option<PublicationStamp> {
        self.maps
            .read()
            .ok()
            .and_then(|maps| maps.notification_watermarks.get(identity).cloned())
    }

    /// Apply a freshness fence without installing or removing authorization state.
    pub fn apply_evidence_invalidation(
        &self,
        request: EvidenceInvalidationRequest,
    ) -> Result<(), String> {
        if request.stamp.validate().is_err()
            || request.stamp.generation != request.published_generation
        {
            self.mark_channel_suspect("invalid evidence invalidation publication stamp");
            return Err("invalid evidence invalidation publication stamp".to_owned());
        }
        if request.tenant_id <= 0
            || request.card_id.is_some_and(|value| value <= 0)
            || request.event_id.len() > 128
            || request.operation_id.len() > 128
            || request.event_id.trim().is_empty()
            || request.operation_id.trim().is_empty()
            || request.source_generation == 0
            || request.revoke_fence > request.source_generation
        {
            return Err("invalid evidence invalidation provenance".to_owned());
        }
        if request.card_id.is_some()
            && request.aggregate_type == PublishedEvidenceAggregate::UserCard
            && Some(request.aggregate_id) != request.card_id
        {
            return Err("published USER_CARD aggregate id does not match card scope".to_owned());
        }
        let aggregate = ProjectionAggregateIdentity::new(
            request.tenant_id,
            request.aggregate_type.as_str(),
            request.aggregate_id,
        )
        .map_err(|error| error.to_string())?;
        let mut maps = self
            .maps
            .write()
            .map_err(|_| "memory projection hub lock poisoned".to_owned())?;
        let conflicts = maps
            .notification_watermarks
            .get(&aggregate)
            .is_some_and(|observed| {
                observed.generation == request.stamp.generation && *observed != request.stamp
            })
            || maps.states.get(&aggregate).is_some_and(|state| {
                state.generation == request.stamp.generation
                    && state.publication_stamp().ok().as_ref() != Some(&request.stamp)
            });
        if conflicts {
            maps.suspect("same-generation invalidation publication divergence");
            return Err("same-generation invalidation publication divergence".to_owned());
        }
        if !maps.notification_watermarks.contains_key(&aggregate)
            && maps.notification_watermarks.len() >= MAX_MIRROR_STATES
        {
            maps.suspect("publication notification watermark capacity exhausted");
            return Err("publication notification watermark capacity exhausted".to_owned());
        }
        let completed = maps
            .completed
            .get(&CompletionIdentity {
                aggregate: aggregate.clone(),
                event_id: request.event_id.clone(),
                operation_id: request.operation_id.clone(),
                source_generation: request.source_generation,
            })
            .is_some_and(|receipt| {
                receipt.stamp.generation > request.published_generation
                    && receipt.stamp.validate().is_ok()
                    && receipt.revoke_fence >= request.revoke_fence
                    && receipt.installed_at.elapsed() <= MIRROR_TTL
            });
        if !completed {
            maps.record_pending(
                request.tenant_id,
                request.card_id,
                PendingDeltaEntry {
                    aggregate: Some(aggregate.clone()),
                    event_id: request.event_id,
                    operation_id: request.operation_id,
                    source_generation: request.source_generation,
                    published_stamp: Some(request.stamp.clone()),
                    revoke_class: true,
                    revoke_fence: request.revoke_fence,
                },
            )
            .map_err(|error| error.to_string())?;
        }
        maps.notification_watermarks
            .entry(aggregate)
            .and_modify(|observed| {
                if observed.generation < request.stamp.generation {
                    *observed = request.stamp.clone();
                }
            })
            .or_insert(request.stamp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use astral_types::PublicationSeal;

    use super::{EvidenceInvalidationRequest, MemoryProjectionHub, PublicationStamp};
    use astral_types::PublishedEvidenceAggregate;

    fn request() -> EvidenceInvalidationRequest {
        EvidenceInvalidationRequest {
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 17,
            event_id: "event-2".to_owned(),
            operation_id: "operation-2".to_owned(),
            source_generation: 2,
            revoke_fence: 2,
            published_generation: 1,
            stamp: PublicationStamp::new(
                1,
                "ab".repeat(32),
                PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn same_generation_notification_hash_or_time_conflict_is_sticky() {
        for change_time in [false, true] {
            let hub = MemoryProjectionHub::default();
            let original = request();
            hub.apply_evidence_invalidation(original.clone()).unwrap();
            let mut divergent = original.clone();
            if change_time {
                divergent.stamp.seal = PublicationSeal::from_unix_seconds(1_700_000_001).unwrap();
            } else {
                divergent.stamp.manifest_digest_hex = "cd".repeat(32);
            }
            assert!(hub.apply_evidence_invalidation(divergent).is_err());
            assert!(hub.channel_is_suspect());
            let maps = hub.maps.read().unwrap();
            assert_eq!(maps.pending_count, 1);
            assert_eq!(maps.notification_watermarks.len(), 1);
            assert_eq!(
                maps.notification_watermarks.values().next(),
                Some(&original.stamp)
            );
        }
    }

    #[test]
    fn notification_watermark_preserves_all_stamp_dimensions_when_advancing() {
        let hub = MemoryProjectionHub::default();
        let original = request();
        hub.apply_evidence_invalidation(original.clone()).unwrap();
        let mut newer = original;
        newer.stamp.generation = 2;
        newer.published_generation = 2;
        newer.source_generation = 3;
        hub.apply_evidence_invalidation(newer.clone()).unwrap();
        assert_eq!(
            hub.applied_generation_watermark(
                &super::ProjectionAggregateIdentity::new(7, "USER_CARD", 17).unwrap()
            ),
            Some(2)
        );
        assert_eq!(
            hub.applied_publication_stamp(
                &super::ProjectionAggregateIdentity::new(7, "USER_CARD", 17).unwrap()
            ),
            Some(newer.stamp)
        );
    }

    #[test]
    fn notification_capacity_rejects_new_scope_without_losing_prior_fences() {
        let hub = MemoryProjectionHub::default();
        let request = request();
        {
            let mut maps = hub.maps.write().unwrap();
            for id in 1..=super::MAX_MIRROR_STATES {
                let identity =
                    super::ProjectionAggregateIdentity::new(8, "USER_CARD", id as i64).unwrap();
                maps.notification_watermarks
                    .insert(identity, request.stamp.clone());
            }
        }
        assert!(hub.apply_evidence_invalidation(request).is_err());
        assert!(hub.channel_is_suspect());
        let maps = hub.maps.read().unwrap();
        assert_eq!(maps.notification_watermarks.len(), super::MAX_MIRROR_STATES);
        assert_eq!(maps.pending_count, 0);
    }

    #[test]
    fn malformed_stamp_or_generation_disagreement_cannot_advance_watermark() {
        for field in 0..3 {
            let hub = MemoryProjectionHub::default();
            let mut invalid = request();
            match field {
                0 => invalid.stamp.generation = 0,
                1 => invalid.stamp.manifest_digest_hex = "AB".repeat(32),
                2 => invalid.published_generation += 1,
                _ => unreachable!(),
            }
            assert!(hub.apply_evidence_invalidation(invalid).is_err());
            assert!(hub.channel_is_suspect());
            let maps = hub.maps.read().unwrap();
            assert!(maps.notification_watermarks.is_empty());
            assert_eq!(maps.pending_count, 0);
        }
    }
}
