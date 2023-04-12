use crate::{ip_monitor::IpMonitor, Result};
use log::{error, info};
use quick_error::quick_error;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs},
    option::Option,
    process::exit,
    str::FromStr,
    sync::mpsc::{channel, Receiver, Sender, TryRecvError},
    time::{Duration, SystemTime},
};

quick_error! {
    #[derive(Debug)]
    pub enum UtilError {
        AddrResolveError
    }
}

pub fn tcp_ping(addr: &str) -> Result<u16> {
    let addr = addr.to_socket_addrs()?.next();
    if addr.is_none() {
        return Err(Box::new(UtilError::AddrResolveError));
    }
    let timeout = Duration::from_secs(3);
    let start_time = SystemTime::now();
    let stream = TcpStream::connect_timeout(&addr.unwrap(), timeout)?;
    stream.peer_addr()?;
    let d = SystemTime::now().duration_since(start_time)?;
    Ok(d.as_millis() as u16)
}

fn get_ifs() -> Vec<(String, IpAddr)> {
    let ifs = match if_addrs::get_if_addrs() {
        Ok(ifs) => ifs,
        Err(err) => {
            println!("Get Net Intercafes failed: {err}");
            exit(500)
        }
    };

    let mut ips = Vec::with_capacity(ifs.len());
    for i in ifs {
        if !i.is_loopback() {
            ips.push((i.name.clone(), i.ip()))
        }
    }
    ips
}

pub fn get_ip_by_if_name(if_name: &str) -> Option<String> {
    let ifs = get_ifs();
    for i in ifs {
        if i.0.contains(if_name) && i.1.is_ipv4() {
            return Some(i.1.to_string());
        }
    }
    None
}

pub fn select_ip() -> Option<String> {
    let ips = get_ifs();
    if ips.is_empty() {
        return None;
    }
    if ips.len() == 1 {
        return Some(ips[0].1.to_string());
    }

    println!("Please select your IP:");
    for (n, ip) in ips.iter().enumerate() {
        println!("    {}. {} - {}", n + 1, ip.1, ip.0);
    }

    for t in 1..=3 {
        let mut input_text = String::new();
        io::stdin()
            .read_line(&mut input_text)
            .expect("failed to read from stdin");
        let trimmed = input_text.trim();
        if let Ok(i) = trimmed.parse::<usize>() {
            if i > 0 && i <= ips.len() {
                let ip = ips[i - 1].1.to_string();
                println!("you choose {}", ip);
                return Some(ip);
            }
        }
        println!("not a valid index number, {}/3", t);
    }
    println!("invalid input for 3 times");
    None
}

pub fn get_ip(dev: &str) -> Result<Ipv4Addr> {
    let ifs = if_addrs::get_if_addrs()?;
    for int in ifs {
        if let IpAddr::V4(ip) = int.addr.ip() {
            if int.name == dev {
                return Ok(ip);
            }
        }
    }
    Ok(Ipv4Addr::UNSPECIFIED)
}

#[derive(Debug)]
pub struct IpFilter {
    rx: Receiver<Ipv4Addr>,
    ip: Ipv4Addr,
    min: Ipv4Addr,
    max: Ipv4Addr,
    dev: String,
}

pub fn monitor(dev: &str, tx: Sender<Ipv4Addr>) -> Result<()> {
    let mut m = IpMonitor::new(dev)?;
    loop {
        let ip = m.ip()?;
        if let Err(e) = tx.send(ip) {
            error!("send error: {}", e);
            return Err("send error".into());
        }
    }
}

impl IpFilter {
    pub fn from_env() -> Option<Self> {
        let min = match std::env::var("SRUN_MIN_IP") {
            Ok(min) => min,
            Err(_) => return None,
        };
        let min = Ipv4Addr::from_str(&min).unwrap();
        let max = Ipv4Addr::from_str(&std::env::var("SRUN_MAX_IP").unwrap()).unwrap();
        let dev = std::env::var("SRUN_INTERFACE").unwrap();
        let dev2 = dev.clone();

        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let r = monitor(&dev2, tx);
            if let Err(e) = r {
                error!("monitor error: {}", e);
            }
        });
        let ip = get_ip(&dev).unwrap();
        Some(IpFilter {
            rx,
            ip,
            min,
            max,
            dev,
        })
    }

    pub fn wait(&mut self) -> Result<bool> {
        let mut new_ip = self.ip;
        let mut changed = false;
        loop {
            match self.rx.try_recv() {
                Ok(ip) => {
                    new_ip = ip;
                    changed = true;
                }
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        if new_ip != self.ip {
            self.ip = new_ip;
            info!("{}: {}", self.dev, self.ip);
        }
        if self.ip >= self.min && self.ip < self.max {
            return Ok(changed);
        }
        loop {
            let ip = self.rx.recv()?;
            self.ip = ip;
            info!("{} changed: {}", self.dev, ip);
            if self.ip >= self.min && self.ip < self.max {
                return Ok(true);
            }
        }
    }
}

#[test]
fn test_get_ips() {
    select_ip();
}

#[test]
fn test_get_ip_by_name() {
    println!("{:?}", get_ip_by_if_name("wlp3s0"));
}

#[test]
fn test_tcp_ping() {
    let p = tcp_ping("baidu.com:80");
    println!("{:?}", p);
}
