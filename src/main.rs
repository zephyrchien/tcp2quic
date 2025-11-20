mod client;
mod common;
mod server;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::exit;

const USAGE: &str = concat!(
    "usage: tcp2quic <mode> <local_addr> <remote_addr> <options>\n",
    "\n",
    "tcp2quic -c <local_addr> <remote_addr> <options>\n",
    "tcp2quic -s <local_addr> <remote_addr> <options>"
);

enum Mode {
    Client,
    Server,
}

struct Config {
    mode: Mode,
    local: SocketAddr,
    remote: SocketAddr,
    hostname: String,
}

impl Config {
    fn from_args() -> Self {
        let args: Vec<String> = env::args().collect();
        if args.len() < 4 {
            eprintln!("{}", USAGE);
            exit(1);
        }
        let mode = match args[1].as_str() {
            "-s" => Mode::Server,
            "-c" => Mode::Client,
            _ => {
                eprintln!("{}", USAGE);
                exit(1);
            }
        };

        Config {
            mode,
            local: args[2]
                .to_socket_addrs()
                .expect("invalid local addr")
                .next()
                .unwrap(),
            remote: args[3]
                .to_socket_addrs()
                .expect("invalid remote addr")
                .next()
                .unwrap(),
            hostname: String::from(if args.len() == 5 {
                &args[4]
            } else {
                "localhost"
            }),
        }
    }
}

#[tokio::main]
async fn main() {
    let c = Config::from_args();
    if let Err(e) = match c.mode {
        Mode::Client => client::run(c.local, c.remote, c.hostname).await,
        Mode::Server => server::run(c.local, c.remote, c.hostname).await,
    } {
        eprintln!("Error: {}", e);
        exit(1);
    }
}
