mod user;
pub use user::User;

mod srun;
pub use srun::*;

mod xencode;
pub use xencode::param_i;

mod file;
pub use file::read_config_from_file;

mod ip_monitor;
mod utils;

#[cfg(feature = "ureq")]
mod http_client;

pub use utils::select_ip;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
