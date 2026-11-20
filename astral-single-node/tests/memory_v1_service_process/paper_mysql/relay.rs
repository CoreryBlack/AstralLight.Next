//! memory—v1: Owned loopback relay used only by the paper service child.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ColdStreams {
    accepted: usize,
    closed: usize,
}

pub(super) struct Relay {
    addr: SocketAddr,
    streams: watch::Receiver<ColdStreams>,
    cutoff: Option<oneshot::Sender<()>>,
    task: JoinHandle<(TcpListener, ColdStreams)>,
}

impl Relay {
    pub(super) async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind private MySQL relay");
        let addr = listener.local_addr().expect("private relay address");
        let (reports, streams) = watch::channel(ColdStreams::default());
        let (cutoff, mut cut) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut counts = ColdStreams::default();
            let mut active = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    Some(result) = active.join_next(), if !active.is_empty() => {
                        result.expect("private relay task completes");
                        counts.closed += 1;
                        reports.send_replace(counts);
                    }
                    _ = &mut cut => {
                        assert_eq!(counts.closed, counts.accepted, "cold MySQL streams still active at cutoff");
                        return (listener, counts);
                    }
                    accepted = listener.accept() => {
                        let (mut client, _) = accepted.expect("accept private relay connection");
                        assert!(counts.accepted < 16 && active.len() < 4, "private relay connection budget exceeded");
                        counts.accepted += 1;
                        reports.send_replace(counts);
                        active.spawn(async move {
                            let mut server = timeout(Duration::from_secs(5), TcpStream::connect(upstream))
                                .await.expect("relay upstream deadline").expect("connect to dedicated MySQL");
                            tokio::io::copy_bidirectional(&mut client, &mut server)
                                .await.expect("relay cold MySQL stream");
                        });
                    }
                }
            }
        });
        Self {
            addr,
            streams,
            cutoff: Some(cutoff),
            task,
        }
    }

    pub(super) fn port(&self) -> u16 {
        self.addr.port()
    }

    // Keep the port reserved with no accept loop; no other local listener can take over.
    pub(super) async fn cut(mut self) -> (TcpListener, usize) {
        let drained = *timeout(
            Duration::from_secs(5),
            self.streams
                .wait_for(|counts| counts.accepted > 0 && counts.closed == counts.accepted),
        )
        .await
        .expect("the child releases its cold MySQL connections")
        .expect("cold relay stays running until cutoff");
        self.cutoff
            .take()
            .unwrap()
            .send(())
            .expect("request private cutoff");
        let (reserved, stopped) = (&mut self.task).await.expect("stop the private relay");
        assert!(
            drained == stopped,
            "new MySQL traffic arrived during the cutoff"
        );
        (reserved, stopped.closed)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
