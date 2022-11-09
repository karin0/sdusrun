use std::env;

fn main() {
    let auth_server_ip = env!(
        "AUTH_SERVER_IP",
        "Expect env AUTH_SERVER_IP, export AUTH_SERVER_IP=10.0.0.1"
    );
    println!("ENV AUTH_SERVER_IP = {auth_server_ip}");
}
