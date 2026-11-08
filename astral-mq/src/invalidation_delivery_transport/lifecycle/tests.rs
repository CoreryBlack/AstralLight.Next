use super::*;
use std::sync::mpsc;
use tokio::sync::oneshot;

fn blocked_task() -> (JoinHandle<()>, mpsc::Sender<()>) {
    let (started, running) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let join = tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        wait.recv().unwrap();
    });
    running.recv_timeout(Duration::from_secs(1)).unwrap();
    (join, release)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_keeps_unreaped_owner_until_independent_completion() {
    let lifecycle = InvalidationTransportLifecycle::new(0);
    let (task, release) = blocked_task();
    let mut join = Some(task);
    let result =
        abort_and_reap_transport_join(&mut join, "blocked owner", Instant::now(), &lifecycle).await;
    let retained = lifecycle.lock_snapshot().reapers.len();
    release.send(()).unwrap();
    lifecycle
        .wait_for_reapers(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(result.contains("unknown"));
    assert!(join.is_none());
    assert_eq!(retained, 1);
    assert!(lifecycle.lock_snapshot().reapers.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_mtls_owner_transfers_all_connection_ownership() {
    let lifecycle = InvalidationTransportLifecycle::new(1);
    let owner = lifecycle.clone();
    let (started, running) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let (guard_ready, guard_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = MtlsConnectionsGuard::new(owner);
        connections.spawn_blocking(move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        });
        guard_ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    guard_rx.await.unwrap();
    running.recv_timeout(Duration::from_secs(1)).unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let retained = lifecycle.lock_snapshot().reapers.len();
    release.send(()).unwrap();
    lifecycle
        .wait_for_reapers(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(retained, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_drain_obeys_shared_deadline_and_retains_unknown_tasks() {
    let lifecycle = InvalidationTransportLifecycle::new(0);
    lifecycle.set_shutdown_deadline(Instant::now());
    let mut connections = MtlsConnectionsGuard::new(lifecycle.clone());
    let (started, running) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    connections.spawn_blocking(move || {
        started.send(()).unwrap();
        wait.recv().unwrap();
    });
    running.recv_timeout(Duration::from_secs(1)).unwrap();
    let start = Instant::now();
    let result = drain_mtls_connections(&mut connections, Duration::from_secs(5)).await;
    let elapsed = start.elapsed();
    drop(connections);
    let retained = lifecycle.lock_snapshot().reapers.len();
    release.send(()).unwrap();
    lifecycle
        .wait_for_reapers(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(result.unwrap_err().contains("unknown"));
    assert_eq!(retained, 1);
    assert!(elapsed < Duration::from_millis(250));
}

#[tokio::test]
async fn connection_panics_remain_a_failure_after_reaping() {
    let lifecycle = InvalidationTransportLifecycle::new(0);
    let mut connections = MtlsConnectionsGuard::new(lifecycle.clone());
    let (started, running) = oneshot::channel();
    connections.spawn(async move {
        started.send(()).unwrap();
        panic!("injected connection panic");
    });
    running.await.unwrap();
    tokio::task::yield_now().await;
    drop(connections);
    let failure = lifecycle
        .wait_for_reapers(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(failure.contains("connection join failed"));
}

#[tokio::test]
async fn shutdown_keeps_owner_failure_sticky() {
    let lifecycle = InvalidationTransportLifecycle::new(0);
    lifecycle.begin_shutdown();
    run_owned_transport_task(lifecycle.clone(), "stopping owner", async {
        Err("injected failure during shutdown".into())
    })
    .await;
    assert!(lifecycle
        .mark_shutdown_complete()
        .unwrap_err()
        .contains("injected failure during shutdown"));
    assert!(
        matches!(lifecycle.state(), InvalidationTransportLifecycleState::Failed(reason) if reason.contains("injected failure during shutdown"))
    );
}

#[test]
fn mutex_poison_fails_closed() {
    let lifecycle = InvalidationTransportLifecycle::new(1);
    let poisoned = lifecycle.inner.clone();
    let task = std::thread::spawn(move || {
        let _guard = poisoned.snapshot.lock().unwrap();
        panic!("inject lifecycle mutex poison");
    });
    assert!(task.join().is_err());
    assert!(
        matches!(lifecycle.state(), InvalidationTransportLifecycleState::Failed(reason) if reason.contains("mutex poisoned"))
    );
}
