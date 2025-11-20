mod client;
mod common;
mod server;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::exit;

const USAGE: &str = concat!(
    "usage:\n",
    "tcp2quic -c <tcp_addr> <quic_addr> <sni=localhost>\n",
    "tcp2quic -s <quic_addr> <tcp_addr> <common_name=localhost>"
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
    match c.mode {
        Mode::Client => client::run(c.local, c.remote, c.hostname).await,
        Mode::Server => server::run(c.local, c.remote, c.hostname).await,
    }
}
