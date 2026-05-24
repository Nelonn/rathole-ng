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

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    use std::os::windows::io::AsRawSocket;
    let handle = socket.as_raw_socket();
    let mut enable: u32 = 0;
    let mut bytes_returned: u32 = 0;

    let res = unsafe {
        WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            &mut enable as *mut _ as LPVOID,
            std::mem::size_of_val(&enable) as DWORD,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    println!("WSAIoctl res: {}", res);

    let socket_clone = std::sync::Arc::new(socket);
    let socket_c = socket_clone.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match socket_c.recv_from(&mut buf).await {
                Ok((n, addr)) => println!("recv_from ok: {} bytes from {}", n, addr),
                Err(e) => {
                    println!("recv_from err: {:?}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    let target: std::net::SocketAddr = "127.0.0.1:2346".parse().unwrap();

    for i in 0..10 {
        match socket_clone.try_send_to(b"hello", target) {
            Ok(n) => println!("try_send_to {} ok: {}", i, n),
            Err(e) => println!("try_send_to {} err: {:?}", i, e),
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

#[cfg(not(windows))]
fn main() {
    println!("This example is only for Windows.");
}
