use crate::Result;
use log::debug;
use quick_error::quick_error;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs},
    option::Option,
    process::exit,
    str::FromStr,
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

#[derive(Debug, Clone)]
pub struct IpFilter {
    min: Ipv4Addr,
    max: Ipv4Addr,
    int_prefix: Option<String>,
    ifs: Option<Vec<if_addrs::Interface>>,
}

impl IpFilter {
    pub fn from_env() -> Option<Self> {
        if let Ok(min) = std::env::var("SRUN_MIN_IP") {
            let min = Ipv4Addr::from_str(&min).unwrap();
            let max = Ipv4Addr::from_str(&std::env::var("SRUN_MAX_IP").unwrap()).unwrap();
            Some(Self {
                min,
                max,
                int_prefix: std::env::var("SRUN_INTERFACE_PREFIX").ok(),
                ifs: None,
            })
        } else {
            None
        }
    }

    fn refresh(&mut self) {
        self.ifs = Some(if_addrs::get_if_addrs().unwrap());
    }

    pub fn check(&mut self) -> bool {
        self.refresh();
        for int in self.ifs.as_ref().unwrap() {
            if let Some(prefix) = &self.int_prefix {
                if !int.name.starts_with(prefix) {
                    continue;
                }
            }
            if let IpAddr::V4(ip) = int.addr.ip() {
                if ip >= self.min && ip < self.max {
                    debug!("found ip: {:?}", int);
                    return true;
                }
            }
        }
        false
    }

    pub fn current(&self) -> Option<String> {
        if let Some(pre) = &self.int_prefix {
            if let Some(ifs) = &self.ifs {
                let mut name = None;
                let mut res = vec![];
                for int in ifs {
                    if let IpAddr::V4(ip) = int.addr.ip() {
                        if int.name.starts_with(pre) {
                            res.push(if let Some(last) = name {
                                if int.name.eq(last) {
                                    ip.to_string()
                                } else {
                                    format!("{}: {}", int.name, ip)
                                }
                            } else {
                                format!("{}: {}", int.name, ip)
                            });
                            name = Some(&int.name);
                        }
                    }
                }
                return if res.is_empty() {
                    None
                } else {
                    Some(res.join(", "))
                };
            }
        }
        None
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
