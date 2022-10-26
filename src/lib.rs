// Jackson Coxson

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::{
        mpsc::{channel, Sender},
        Arc,
    },
};

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use log::error;

pub fn start_loopback(expected_addrs: Vec<Ipv4Addr>, bind_addr: SocketAddrV4) -> Sender<()> {
    // Create the handle
    let (tx, rx) = channel();

    // Read the keys to memory
    let server_private = include_str!("../keys/server_privatekey")[..44].to_string();
    let client_public = include_str!("../keys/client_publickey")[..44].to_string();

    let server_private = X25519SecretKey::from_str(&server_private).unwrap();
    let client_public = X25519PublicKey::from_str(&client_public).unwrap();

    let tun = boringtun::noise::Tunn::new(
        Arc::new(server_private),
        Arc::new(client_public),
        None,
        None,
        0,
        None,
    )
    .unwrap();

    let socket = std::net::UdpSocket::bind(bind_addr).unwrap();

    std::thread::spawn(move || {
        let mut ready = false;
        loop {
            // Attempt to read from the UDP socket
            socket
                .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                .unwrap();
            let mut buf = [0_u8; 2048]; // we can use a small buffer because it will tell us if more is needed
            match socket.recv_from(&mut buf) {
                Ok((size, endpoint)) => {
                    let raw_buf = buf[..size].to_vec();

                    // Parse it with boringtun
                    let mut unencrypted_buf = [0; 65536];
                    let p = tun.decapsulate(Some(endpoint.ip()), &raw_buf, &mut unencrypted_buf);

                    match p {
                        boringtun::noise::TunnResult::Done => {
                            // literally nobody knows what to do with this
                            if !ready {
                                ready = true;
                                println!("Ready!!");
                            }
                        }
                        boringtun::noise::TunnResult::Err(_) => {
                            // don't care
                        }
                        boringtun::noise::TunnResult::WriteToNetwork(b) => {
                            socket.send_to(b, endpoint).unwrap();
                            loop {
                                let p =
                                    tun.decapsulate(Some(endpoint.ip()), &[], &mut unencrypted_buf);
                                match p {
                                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                        socket.send_to(b, endpoint).unwrap();
                                    }
                                    _ => break,
                                }
                            }
                        }
                        boringtun::noise::TunnResult::WriteToTunnelV4(b, _addr) => {
                            // Check to make sure this isn't some background noise packet
                            let source = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
                            let target = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
                            if !expected_addrs.contains(&source)
                                || !expected_addrs.contains(&target)
                            {
                                continue;
                            }

                            // Swap bytes 12-15 with 16-19
                            b.swap(12, 16);
                            b.swap(13, 17);
                            b.swap(14, 18);
                            b.swap(15, 19);

                            let mut buf = [0_u8; 2048];
                            match tun.encapsulate(b, &mut buf) {
                                boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                    socket.send_to(b, endpoint).unwrap();
                                }
                                _ => {
                                    println!("Unexpected result");
                                }
                            }
                        }
                        boringtun::noise::TunnResult::WriteToTunnelV6(_b, _addr) => {
                            panic!("IPv6 not supported");
                        }
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock => {}
                    std::io::ErrorKind::TimedOut => {}
                    _ => {
                        error!("Error receiving: {}", e);
                        return;
                    }
                },
            }
            // Die if instructed or if the handle was destroyed
            match rx.try_recv() {
                Ok(_) => return,
                Err(e) => match e {
                    std::sync::mpsc::TryRecvError::Empty => continue,
                    std::sync::mpsc::TryRecvError::Disconnected => return,
                },
            }
        }
    });

    tx
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        str::FromStr,
    };

    use super::*;

    #[test]
    fn pls_yeet() {
        let endpoint_addr = Ipv4Addr::from_str("10.7.0.10").unwrap();
        let self_addr = Ipv4Addr::from_str("10.7.0.1").unwrap();
        let bind_addr = SocketAddrV4::from_str("127.0.0.1:51820").unwrap();
        let _handle = start_loopback(vec![endpoint_addr, self_addr], bind_addr);

        let num = 1000;
        let size = 100_000;

        // Create TCP listener
        let listener = std::net::TcpListener::bind("0.0.0.0:3000").unwrap();
        let (send_ready, ready) = channel();

        // A place to store the test data
        let tests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let spawn_tests = tests.clone();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // Create test data
            let mut local_tests = Vec::new();
            for _ in 0..num {
                let mut test = Vec::new();
                for _ in 0..size {
                    test.push(rand::random::<u8>());
                }
                tests.lock().unwrap().extend(test.clone());
                local_tests.push(test);
            }

            // Wait until we're ready to send the test
            ready.recv().unwrap();

            // Send the test data
            for test in local_tests {
                stream.write_all(&test).unwrap();
                std::thread::sleep(std::time::Duration::from_nanos(1));
            }
        });

        let mut connector =
            std::net::TcpStream::connect(SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 1), 3000))
                .unwrap();
        send_ready.send(()).unwrap();

        // Collect the test data
        let mut collected_tests: Vec<u8> = Vec::new();

        let current_time = std::time::Instant::now();

        loop {
            let mut buf = [0_u8; 2048];
            match connector.read(&mut buf) {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                    let buf = &buf[0..size];
                    collected_tests.extend(buf);
                }
                Err(_e) => {
                    break;
                }
            }
        }

        println!("Elapsed time: {:?}", current_time.elapsed());
        println!(
            "MB/s: {:?}",
            collected_tests.len() as f64 / current_time.elapsed().as_secs_f64()
        );

        // Compare the two
        println!("Testing length");
        assert_eq!(collected_tests.len(), spawn_tests.lock().unwrap().len());
        println!("Testing contents");
        assert_eq!(collected_tests, spawn_tests.lock().unwrap()[..]);

        println!("All tests passed");
    }
}
