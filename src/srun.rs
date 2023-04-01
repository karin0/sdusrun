use crate::{
    param_i,
    srun::LoginResult::{Failed, Logged, Success},
    utils::{self, get_ip_by_if_name, IpFilter},
    Result, User,
};
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use md5::Md5;
use once_cell::unsync::OnceCell;
use quick_error::quick_error;
use serde::{de::DeserializeOwned, Deserialize};
use sha1::{Digest, Sha1};
use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const PATH_INDEX: &str = "/index_1.html";
const PATH_GET_CHALLENGE: &str = "/cgi-bin/get_challenge";
const PATH_PORTAL: &str = "/cgi-bin/srun_portal";
const PATH_USER_INFO: &str = "/cgi-bin/rad_user_info";

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36";
const CALLBACK_NAME: &str = "jQuery112407419864172676014_1566720734115";

#[derive(Default, Debug)]
pub struct SrunClient {
    auth_server: String,

    username: String,
    password: String,
    ip: String,
    detect_ip: bool,
    strict_bind: bool,

    retry_delay: u32, // millis
    retry_times: u32,
    test_before_login: bool,

    acid: i32,
    double_stack: i32,
    os: String,
    name: String,

    token: String,
    n: i32,
    utype: i32,
    time: u64,

    http: OnceCell<ureq::Agent>,
    http_redir: OnceCell<ureq::Agent>,
    referer: Option<String>,
    ip_filter: Option<IpFilter>,
}

quick_error! {
    #[derive(Debug)]
    pub enum SrunError {
        GetChallengeFailed
        IpUndefinedError
        NoAcidError
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LoginResult {
    Success,
    Logged(String),
    Failed,
}

impl SrunClient {
    pub fn new_from_user(auth_server: &str, user: User) -> Self {
        let ip = user
            .ip
            .unwrap_or_else(|| get_ip_by_if_name(&user.if_name.unwrap()).unwrap_or_default());
        let ip_filter = IpFilter::from_env();
        if let Some(f) = &ip_filter {
            println!("using {:?}", f);
        }
        Self {
            auth_server: auth_server.to_owned(),
            username: user.username,
            password: user.password,
            ip,
            acid: 1,
            n: 200,
            utype: 1,
            os: "Windows 10".to_string(),
            name: "Windows".to_string(),
            retry_delay: 300,
            retry_times: 2,
            ip_filter,
            ..Default::default()
        }
    }

    pub fn new_for_logout(auth_server: &str, username: &str, ip: &str) -> Self {
        Self {
            auth_server: auth_server.to_owned(),
            username: username.to_owned(),
            ip: ip.to_owned(),
            ..Default::default()
        }
    }

    pub fn set_detect_ip(mut self, b: bool) -> Self {
        self.detect_ip = b;
        self
    }

    pub fn set_strict_bind(mut self, b: bool) -> Self {
        self.strict_bind = b;
        self
    }

    pub fn set_double_stack(mut self, b: bool) -> Self {
        self.double_stack = b as i32;
        self
    }

    pub fn set_n(&mut self, n: i32) {
        self.n = n;
    }

    pub fn set_type(&mut self, utype: i32) {
        self.utype = utype;
    }

    pub fn set_acid(&mut self, acid: i32) {
        self.acid = acid;
    }

    pub fn set_os(&mut self, os: &str) {
        self.os = os.to_owned();
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_owned();
    }

    pub fn set_retry_delay(&mut self, d: u32) {
        self.retry_delay = d;
    }

    pub fn set_retry_times(&mut self, t: u32) {
        self.retry_times = t;
    }

    pub fn set_test_before_login(mut self, b: bool) -> Self {
        self.test_before_login = b;
        self
    }

    #[cfg(feature = "ureq")]
    fn ureq_middleware(
        req: ureq::Request,
        next: ureq::MiddlewareNext,
    ) -> std::result::Result<ureq::Response, ureq::Error> {
        let req = req
            .set("DNT", "1")
            .set("X-Requested-With", "XMLHttpRequest")
            .set("Sec-Fetch-Mode", "cors")
            .set("Sec-Fetch-Site", "same-origin");
        next.handle(req)
    }

    #[cfg(feature = "ureq")]
    pub fn http_builder(&self, redirects: u32) -> ureq::AgentBuilder {
        let client = ureq::AgentBuilder::new()
            .middleware(Self::ureq_middleware)
            .user_agent(USER_AGENT)
            .redirects(redirects)
            .timeout(Duration::from_secs(10));
        if self.strict_bind && !self.ip.is_empty() {
            todo!()
            // let local_addr = IpAddr::from_str(&self.ip).unwrap();
            // client.local_address(local_addr)
        } else {
            client
        }
    }

    #[cfg(feature = "ureq")]
    pub fn get_http_client(&self) -> Result<&ureq::Agent> {
        Ok(self.http.get_or_init(|| self.http_builder(0).build()))
    }

    #[cfg(feature = "ureq")]
    pub fn get_http_client_redir(&self) -> Result<&ureq::Agent> {
        Ok(self.http_redir.get_or_init(|| self.http_builder(5).build()))
    }

    #[cfg(feature = "ureq_connector")]
    fn _get_http_client(&self) -> Result<ureq::Agent> {
        use crate::http_client::BindConnector;
        use std::net::SocketAddr;

        Ok(if self.strict_bind && !self.ip.is_empty() {
            let local_addr_ip = IpAddr::from_str(&self.ip)?;
            ureq::AgentBuilder::new()
                .connector(BindConnector::new_bind(SocketAddr::new(local_addr_ip, 0)))
                .timeout_connect(Duration::from_secs(5))
                .build()
        } else {
            ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .build()
        })
    }

    #[cfg(feature = "ureq")]
    fn cli_get_req(&self, cli: &ureq::Agent, path: &str) -> ureq::Request {
        let r = cli.get(format!("{}{}", self.auth_server, path).as_str());
        if let Some(s) = &self.referer {
            r.set("Referer", s)
        } else {
            r
        }
    }

    #[cfg(feature = "ureq")]
    fn get_req(&self, path: &str) -> Result<ureq::Request> {
        Ok(self.cli_get_req(self.get_http_client()?, path))
    }

    #[cfg(feature = "ureq")]
    fn get_req_redir(&self, path: &str) -> Result<ureq::Request> {
        Ok(self.cli_get_req(self.get_http_client_redir()?, path))
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str, query: &[(&str, &str)]) -> Result<T> {
        let req = self.get_req(path)?;
        Ok({
            #[cfg(feature = "reqwest")]
            {
                let resp = req.query(&query).send()?.bytes()?;
                serde_json::from_slice(&resp[CALLBACK_NAME.len() + 1..resp.len() - 1])
            }
            #[cfg(feature = "ureq")]
            {
                // FIXME
                let mut req = req;
                for (k, v) in query {
                    req = req.query(k, v)
                }
                let resp = req.call()?.into_string()?;
                let resp = resp.as_bytes();
                serde_json::from_slice(&resp[CALLBACK_NAME.len() + 1..resp.len() - 1])
            }
        }?)
    }

    fn get_text_redir(&self, path: &str) -> Result<String> {
        let req = self.get_req_redir(path)?;
        Ok({
            #[cfg(feature = "reqwest")]
            {
                req.send()?.text()?
            }
            #[cfg(feature = "ureq")]
            {
                req.call()?.into_string()?
            }
        })
    }

    fn get_token(&mut self) -> Result<String> {
        if !self.detect_ip && self.ip.is_empty() {
            println!("need ip");
            return Err(Box::new(SrunError::IpUndefinedError));
        }

        self.time = unix_second() - 2;
        let time = self.time.to_string();

        let query = vec![
            ("callback", CALLBACK_NAME),
            ("username", &self.username),
            ("ip", &self.ip),
            ("_", &time),
        ];

        let challenge: ChallengeResponse = self.get_json(PATH_GET_CHALLENGE, &query)?;
        info!("challenge: {:?}", challenge);
        match challenge.challenge.clone() {
            Some(token) => {
                self.token = token;
                if self.detect_ip && !challenge.client_ip.is_empty() {
                    self.ip = challenge.client_ip;
                }
            }
            None => {
                return Err(Box::new(SrunError::GetChallengeFailed));
            }
        };
        Ok(self.token.clone())
    }

    fn refresh(&mut self) -> Result<()> {
        let index = self.get_req(PATH_INDEX)?.call()?;
        let base = url::Url::parse(index.get_url())?;
        debug!("index: {index:?}");
        let url = index
            .header("Location")
            .ok_or_else(|| Box::new(SrunError::NoAcidError))?
            .to_owned();
        let p = match url.find("ac_id=") {
            Some(p) => p + 6,
            _ => return Err(Box::new(SrunError::NoAcidError)),
        };
        let q = match url[p..].find('&') {
            Some(q) => p + q,
            _ => url.len(),
        };
        let acid = url[p..q].parse::<i32>()?;
        let url = base.join(&url)?.to_string();
        info!("acid: {acid} ({url})");
        self.referer = Some(url);
        self.acid = acid;
        Ok(())
    }

    pub fn login(&mut self) -> Result<LoginResult> {
        if self.test_before_login {
            if let Ok(d) = utils::tcp_ping("baidu.com:80") {
                println!(
                    "Network already connected: tcping baidu.com:80, delay: {}ms",
                    d
                );
                return Ok(Logged("baidu.com:80".to_owned()));
            }
        }

        let msg = self.user_info()?;
        if msg.contains("not_online_error") {
            warn!("offline: {}", msg);
        } else {
            return Ok(Logged(msg));
        }

        self.refresh()?;
        // this will detect ip from response if detect_ip
        self.get_token()?;

        if self.ip.is_empty() {
            return Err(Box::new(SrunError::IpUndefinedError));
        }

        let hmd5 = {
            let mut mac = Hmac::<Md5>::new_from_slice(self.token.as_bytes())?;
            mac.update(self.password.as_bytes());
            let result = mac.finalize();
            format!("{:x}", result.into_bytes())
        };

        let param_i = param_i(
            &self.username,
            &self.password,
            &self.ip,
            self.acid,
            &self.token,
        );

        let check_sum = {
            let check_sum = vec![
                "",
                &self.username,
                &hmd5,
                &self.acid.to_string(),
                &self.ip,
                &self.n.to_string(),
                &self.utype.to_string(),
                &param_i,
            ]
            .join(&self.token);
            let mut sha1_hasher = Sha1::new();
            sha1_hasher.update(check_sum);
            format!("{:x}", sha1_hasher.finalize())
        };

        debug!("will try at most {} times...", self.retry_times);
        for ti in 1..=self.retry_times {
            thread::sleep(Duration::from_millis(self.retry_delay as u64));
            let password = format!("{{MD5}}{}", hmd5);
            let ac_id = self.acid.to_string();
            let n = self.n.to_string();
            let utype = self.utype.to_string();
            let double_stack = self.double_stack.to_string();
            let time = self.time.to_string();

            let query = vec![
                ("callback", CALLBACK_NAME),
                ("action", "login"),
                ("username", &self.username),
                ("password", &password),
                ("ip", &self.ip),
                ("ac_id", &ac_id),
                ("n", &n),
                ("type", &utype),
                ("os", &self.os),
                ("name", &self.name),
                ("double_stack", &double_stack),
                ("info", &param_i),
                ("chksum", &check_sum),
                ("_", &time),
            ];

            info!("query: {:?}", query);
            let result: PortalResponse = self.get_json(PATH_PORTAL, &query)?;
            info!("portal: {result:?}");

            if !result.access_token.is_empty() {
                info!("try {}/{}: success", ti, self.retry_times);
                return Ok(Success);
            }
            error!("try {}/{}: failed", ti, self.retry_times);
        }
        Ok(Failed)
    }

    pub fn logout(&mut self) -> Result<()> {
        if self.detect_ip {
            self.get_token()?;
        }

        let ac_id = self.acid.to_string();
        let time = unix_second().to_string();
        let query = vec![
            ("callback", CALLBACK_NAME),
            ("action", "logout"),
            ("username", &self.username),
            ("ip", &self.ip),
            ("ac_id", &ac_id),
            ("_", &time),
        ];

        let result: PortalResponse = self.get_json(PATH_PORTAL, &query)?;

        println!("{:#?}", result);
        Ok(())
    }

    pub fn user_info(&mut self) -> Result<String> {
        self.get_text_redir(PATH_USER_INFO)
    }

    fn current_ip(&self) -> Option<String> {
        self.ip_filter.as_ref().and_then(|f| f.current())
    }

    pub fn daemon(&mut self) {
        let delay = Duration::from_secs(5);
        let abroad_delay = Duration::from_secs(1);
        let mut abroad = false;
        let mut up = false;

        loop {
            if let Some(f) = self.ip_filter.as_mut() {
                if f.check() {
                    if abroad {
                        if let Some(ip) = self.current_ip() {
                            info!("back: {ip}");
                        } else {
                            info!("back");
                        }
                        abroad = false;
                    }
                } else {
                    if !abroad {
                        if let Some(ip) = self.current_ip() {
                            info!("into abroad: {ip}");
                        } else {
                            info!("into abroad");
                        }
                        abroad = true;
                    }
                    thread::sleep(abroad_delay);
                    continue;
                }
            }
            let r = self.login();
            debug!("login: {:?}", r);
            match r {
                Ok(r) => match r {
                    Logged(online) => {
                        if !up {
                            info!("online: {online}");
                            up = true;
                        }
                    }
                    Success => {
                        up = false;
                    }
                    Failed => {
                        error!("srun failed");
                        up = false;
                    }
                },
                Err(e) => {
                    error!("network error: {e}");
                    up = false;
                }
            };
            thread::sleep(delay);
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
struct ChallengeResponse {
    challenge: Option<String>,
    client_ip: String,
    ecode: ECode,
    error_msg: String,
    expire: Option<String>,
    online_ip: String,
    res: String,
    srun_ver: String,
    st: u64,
}

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PortalResponse {
    #[serde(rename(deserialize = "ServerFlag"))]
    server_flag: i32,
    #[serde(rename(deserialize = "ServicesIntfServerIP"))]
    services_intf_server_ip: String,
    #[serde(rename(deserialize = "ServicesIntfServerPort"))]
    services_intf_server_port: String,
    access_token: String,
    checkout_date: u64,
    ecode: ECode,
    error: String,
    error_msg: String,
    client_ip: String,
    online_ip: String,
    real_name: String,
    remain_flux: i32,
    remain_times: i32,
    res: String,
    srun_ver: String,
    suc_msg: String,
    sysver: String,
    username: String,
    wallet_balance: i32,
    st: u64,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ECode {
    I(i32),
    S(String),
}

impl Default for ECode {
    fn default() -> Self {
        Self::I(0)
    }
}

fn unix_second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}
