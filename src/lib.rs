// Jackson Coxson

use std::{
    ffi::CStr,
    net::SocketAddrV4,
    str::FromStr,
    sync::{
        mpsc::{channel, Sender},
        Arc, Mutex,
    },
};

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use libc::{c_char, c_int};
use log::error;
use once_cell::sync::Lazy;

static GLOBAL_HANDLE: Lazy<Mutex<Option<Sender<()>>>> = Lazy::new(|| Mutex::new(None));

pub struct Config {
    server_privatekey: String,
    client_publickey: String,
}

static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config {
    server_privatekey: include_str!("../keys/server_privatekey")[..44].to_string(),
    client_publickey: include_str!("../keys/client_publickey")[..44].to_string(),
}));

#[no_mangle]
/// Sets the server private key
/// # Arguments
/// * `privatekey` - the b64 representation of the privatekey
/// # Returns
/// Null on failure
pub unsafe extern "C" fn set_server_privatekey(privatekey: *const c_char) -> c_int {
    if let Ok(mut config) = CONFIG.lock() {
        let private_key = CStr::from_ptr(privatekey as *mut _);
        if let Ok(private_key_str) = private_key.to_str() {
            config.server_privatekey = private_key_str.to_string();
            return 0;
        }
    }
    return -1;
}

#[no_mangle]
/// Sets the client public key
/// # Arguments
/// * `publickey` - the b64 representation of the public key
/// # Returns
/// Null on failure
pub unsafe extern "C" fn set_client_publickey(publickey: *const c_char) -> c_int {
    if let Ok(mut config) = CONFIG.lock() {
        let public_key = CStr::from_ptr(publickey as *mut _);
        if let Ok(public_key_str) = public_key.to_str() {
            config.client_publickey = public_key_str.to_string();
            return 0;
        }
    }
    return -1;
}

pub fn start_loopback(bind_addr: SocketAddrV4) -> Sender<()> {
    // Create the handle
    let (tx, rx) = channel();

    let config = CONFIG.lock().unwrap();

    let server_private = X25519SecretKey::from_str(&config.server_privatekey).unwrap();
    let client_public = X25519PublicKey::from_str(&config.client_publickey).unwrap();

    let tun = boringtun::noise::Tunn::new(
        Arc::new(server_private),
        Arc::new(client_public),
        None,
        None,
        0,
        None,
    )
    .unwrap();

    std::thread::spawn(move || {
        // Try and wait for the socket to become available
        let mut socket;
        loop {
            match std::net::UdpSocket::bind(bind_addr) {
                Ok(s) => socket = s,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::AddrInUse => {
                        println!("EMP address in use, retrying...");
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    _ => panic!(),
                },
            };
            break;
        }

        let mut ready = false;
        loop {
            // Attempt to read from the UDP socket
            match socket.set_read_timeout(Some(std::time::Duration::from_millis(5))) {
                Ok(_) => {}
                Err(e) => {
                    println!("Unable to set UDP timeout: {:?}\nRebinding to socket", e);
                    std::mem::drop(socket);

                    // Wait until we can rebind to the socket
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        socket = match std::net::UdpSocket::bind(bind_addr) {
                            Ok(s) => s,
                            Err(e) => {
                                println!("Socket not dropped: {:?}", e);
                                continue;
                            }
                        };
                        println!("Rebound to socket!");
                        break;
                    }
                    continue;
                }
            }
            let mut buf = [0_u8; 2048]; // we can use a small buffer because it will tell us if more is needed
            match socket.recv_from(&mut buf) {
                Ok((size, endpoint)) => {
                    // Parse it with boringtun
                    let mut unencrypted_buf = [0; 2176];
                    let p =
                        tun.decapsulate(Some(endpoint.ip()), &buf[..size], &mut unencrypted_buf);

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
                Ok(_) => {
                    println!("EMP instructed to die");
                    return;
                }
                Err(e) => match e {
                    std::sync::mpsc::TryRecvError::Empty => continue,
                    std::sync::mpsc::TryRecvError::Disconnected => {
                        println!("Handle has been destroyed");
                        return;
                    }
                },
            }
        }
    });

    tx
}

#[no_mangle]
/// Starts your emotional damage
/// # Arguments
/// * `bind_addr` - The UDP socket to listen to
/// # Returns
/// A handle to stop further emotional damage.
/// Null on failure
/// # Safety
/// Don't be stupid
pub unsafe extern "C" fn start_emotional_damage(bind_addr: *const c_char) -> c_int {
    // Check if the proxy exists
    if GLOBAL_HANDLE.lock().unwrap().is_some() {
        println!("Proxy already exists, skipping");
        return 0;
    }
    // Check the address
    if bind_addr.is_null() {
        return -1;
    }
    let address = CStr::from_ptr(bind_addr as *mut _);
    let address = match address.to_str() {
        Ok(address) => address,
        Err(_) => return -2,
    };
    let address = match address.parse::<SocketAddrV4>() {
        Ok(address) => address,
        Err(_) => return -3,
    };
    let handle = start_loopback(address);

    *GLOBAL_HANDLE.lock().unwrap() = Some(handle);

    0
}

#[no_mangle]
/// Stops further emotional damage
/// # Arguments
/// * `handle` - The coping mechanism generated by start_emotional_damage
/// # Returns
/// The knowledge of knowing that you couldn't handle failure
/// # Safety
/// Don't be stupid
pub unsafe extern "C" fn stop_emotional_damage() {
    let sender = GLOBAL_HANDLE.lock().unwrap().clone();
    if let Some(sender) = sender {
        if sender.send(()).is_ok() {
            //
        }
    }
    *GLOBAL_HANDLE.lock().unwrap() = None;
}

#[no_mangle]
/// Blocks until Wireguard is ready
/// # Arguments
/// * `timeout` - The timeout in miliseconds to wait for Wireguard
/// # Returns
/// 0 on success, -1 on failure
pub extern "C" fn test_emotional_damage(timeout: c_int) -> c_int {
    // Bind to the testing socket ASAP
    let mut testing_port = 3000_u16;
    let listener;
    loop {
        listener = match std::net::UdpSocket::bind((
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            testing_port,
        )) {
            Ok(l) => l,
            Err(e) => match e.kind() {
                std::io::ErrorKind::AddrInUse => {
                    testing_port += 1;
                    continue;
                }
                _ => {
                    println!("Unable to bind to UDP socket");
                    return -1;
                }
            },
        };
        break;
    }
    listener
        .set_read_timeout(Some(std::time::Duration::from_millis(timeout as u64)))
        .unwrap();

    std::thread::spawn(move || {
        let sender =
            std::net::UdpSocket::bind((std::net::Ipv4Addr::new(127, 0, 0, 1), testing_port + 1))
                .unwrap();
        for _ in 0..10 {
            if sender
                .send_to(&[69], (std::net::Ipv4Addr::new(127, 0, 0, 1), testing_port))
                .is_ok()
            {
                // pass
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });

    let mut buf = [0_u8; 1];
    match listener.recv(&mut buf) {
        Ok(_) => 0,
        Err(e) => {
            println!("Never received test data: {:?}", e);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::Ipv4Addr,
        str::FromStr,
    };

    use super::*;

    #[test]
    fn pls_yeet() {
        let bind_addr = SocketAddrV4::from_str("127.0.0.1:51820").unwrap();
        let _handle = start_loopback(bind_addr);

        let num = 100;
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
