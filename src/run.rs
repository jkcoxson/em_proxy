// Jackson Coxson
// Stand-alone binary to run EMP

mod lib;

use std::{net::SocketAddrV4, str::FromStr};

use lib::start_loopback;

fn main() {
    let bind_addr = SocketAddrV4::from_str("127.0.0.1:51820").unwrap();
    let _handle = start_loopback(bind_addr);

    loop {
        std::thread::sleep(std::time::Duration::from_secs(69));
    }
}
