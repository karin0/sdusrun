use crate::Result;
use log::{debug, warn};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::{
    io::{BufRead, BufReader},
    net::Ipv4Addr,
    process::{Child, ChildStdout, Command, Stdio},
    str::FromStr,
};

pub struct IpMonitor {
    ch: Child,
    out: BufReader<ChildStdout>,
}

impl IpMonitor {
    pub fn new(dev: &str) -> Result<IpMonitor> {
        let mut ch = Command::new("ip")
            .arg("monitor")
            .arg("address")
            .arg("dev")
            .arg(dev)
            .stdout(Stdio::piped())
            .spawn()?;
        let out = ch.stdout.take().unwrap();
        let out = BufReader::new(out);
        Ok(IpMonitor { ch, out })
    }

    pub fn ip(&mut self) -> Result<Ipv4Addr> {
        let mut line = String::new();
        loop {
            let n = self.out.read_line(&mut line)?;
            if n == 0 {
                return Err("EOF".into());
            }
            debug!("line: {}", line);
            let p = match line.find("inet ") {
                Some(p) => p,
                None => continue,
            };
            if line.starts_with("Deleted") {
                return Ok(Ipv4Addr::UNSPECIFIED);
            }
            let line = &line[p + 5..];
            let q = match line.find('/') {
                Some(q) => q,
                None => return Err("invalid line".into()),
            };
            return Ok(Ipv4Addr::from_str(&line[..q])?);
        }
    }
}

impl Drop for IpMonitor {
    fn drop(&mut self) {
        warn!("dropping ip_monitor");
        signal::kill(Pid::from_raw(self.ch.id() as i32), Signal::SIGTERM).unwrap();
    }
}
