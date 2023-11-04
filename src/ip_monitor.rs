use crate::Result;

use futures::stream::StreamExt;
use ip_roam::{Connection, Monitor};
use log::debug;
use tokio::{
    runtime::Runtime,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use std::{marker::PhantomData, net::Ipv4Addr, pin::pin};

#[derive(Debug)]
pub struct IpMonitor<'a> {
    rt: Runtime,
    roam: JoinHandle<()>,
    task: JoinHandle<()>,
    rx: UnboundedReceiver<Ipv4Addr>,
    _phantom: PhantomData<&'a str>,
}

#[derive(Debug)]
struct Label(*const str);

unsafe impl Send for Label {}

async fn sender_task(mon: Monitor, label: Label, tx: UnboundedSender<Ipv4Addr>) {
    let mut s = pin!(mon.stream());
    while let Some(msg) = s.next().await {
        debug!("ip: {msg:?}");
        let addr = msg.addr();
        // SATETY: provided string has a lifetime longer than the `IpMonitor`, which obtains the
        // `Runtime` containing this task.
        if addr.label() == unsafe { &*label.0 } {
            let addr = if msg.is_new() {
                *addr.addr()
            } else {
                Ipv4Addr::UNSPECIFIED
            };
            tx.send(addr).unwrap();
        }
    }
}

impl<'a> IpMonitor<'a> {
    pub fn new(label: &'a str) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _guard = rt.enter();

        let c = Connection::new()?;
        let roam = rt.spawn(c.conn);
        let (tx, rx) = unbounded_channel();
        let task = rt.spawn(sender_task(
            c.handle.monitor,
            Label(label as *const str),
            tx,
        ));

        Ok(Self {
            rt,
            roam,
            task,
            rx,
            _phantom: PhantomData,
        })
    }

    pub fn ip(&mut self) -> Ipv4Addr {
        self.rt.block_on(async { self.rx.recv().await.unwrap() })
    }
}

impl Drop for IpMonitor<'_> {
    fn drop(&mut self) {
        self.task.abort();
        self.roam.abort();
    }
}
