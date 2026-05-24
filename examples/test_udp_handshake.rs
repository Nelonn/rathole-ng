#[cfg(windows)]
#[tokio::main]
async fn main() {
    type DWORD = u32;
    type LPVOID = *mut std::ffi::c_void;
    type LPDWORD = *mut u32;
    type LPWSAOVERLAPPED = *mut std::ffi::c_void;
    type LPWSAOVERLAPPED_COMPLETION_ROUTINE = Option<unsafe extern "system" fn(DWORD, DWORD, LPWSAOVERLAPPED, DWORD)>;

    const SIO_UDP_CONNRESET: u32 = 0x9800000C;

    extern "system" {
        fn WSAIoctl(
            s: std::os::windows::io::RawSocket,
            dwIoControlCode: DWORD,
            lpvInBuffer: LPVOID,
            cbInBuffer: DWORD,
            lpvOutBuffer: LPVOID,
            cbOutBuffer: DWORD,
            lpcbBytesReturned: LPDWORD,
            lpOverlapped: LPWSAOVERLAPPED,
            lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
        ) -> i32;
    }

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    use std::os::windows::io::AsRawSocket;
    unsafe {
        let mut enable: u32 = 0;
        let mut bytes_returned: u32 = 0;
        WSAIoctl(
            client.as_raw_socket(),
            SIO_UDP_CONNRESET,
            &mut enable as *mut _ as LPVOID,
            std::mem::size_of_val(&enable) as DWORD,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        );
    }

    println!("Client sending to closed port...");
    client.send_to(b"packet 1", "127.0.0.1:12345").await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!("Starting server...");
    let server = tokio::net::UdpSocket::bind("127.0.0.1:12345").await.unwrap();

    println!("Client sending to open port...");
    client.send_to(b"packet 2", "127.0.0.1:12345").await.unwrap();

    let mut buf = [0u8; 100];
    let res = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        server.recv_from(&mut buf)
    ).await;

    match res {
        Ok(Ok((n, addr))) => {
            println!("Server received: {} from {}", String::from_utf8_lossy(&buf[..n]), addr);
        }
        Ok(Err(e)) => println!("Server recv error: {}", e),
        Err(_) => println!("Server timed out waiting for packet!"),
    }
}

#[cfg(not(windows))]
fn main() {
    println!("This example is only for Windows.");
}
