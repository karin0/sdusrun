use crate::{ip_monitor::IpMonitor, Result};
use log::info;
use quick_error::quick_error;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs},
    option::Option,
    process::exit,
    str::FromStr,
    sync::{Arc, Condvar, Mutex},
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

type Ctx = (Mutex<(Ipv4Addr, bool)>, Condvar);

#[derive(Debug)]
pub struct IpFilter {
    ctx: Arc<Ctx>,
    min: Ipv4Addr,
    max: Ipv4Addr,
}

pub fn monitor(dev: &str, min: Ipv4Addr, max: Ipv4Addr, ctx: Arc<Ctx>) -> Result<()> {
    let mut m = IpMonitor::new(dev)?;
    loop {
        let ip = m.ip()?;
        *ctx.0.lock().unwrap() = (ip, true);
        if ip >= min && ip < max {
            info!("{}: {}", dev, ip);
            ctx.1.notify_one();
        } else {
            info!("{}: {} (abroad)", dev, ip);
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

        let ip = get_ip(&dev).unwrap();
        let ctx = Arc::new((Mutex::new((ip, false)), Condvar::new()));
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            monitor(&dev, min, max, ctx2).unwrap();
        });
        Some(IpFilter { ctx, min, max })
    }

    pub fn wait(&self) -> bool {
        let mut lock = self.ctx.0.lock().unwrap();
        loop {
            let (ip, changed) = *lock;
            if ip >= self.min && ip < self.max {
                lock.1 = false;
                return changed;
            }
            lock = self.ctx.1.wait(lock).unwrap();
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
