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
    println!("WSAIoctl 0.0.0.0:0 res: {}, error: {}", res, std::io::Error::last_os_error());

    let socket_v6 = tokio::net::UdpSocket::bind("[::]:0").await.unwrap();
    let handle_v6 = socket_v6.as_raw_socket();
    let res_v6 = unsafe {
        WSAIoctl(
            handle_v6,
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
    println!("WSAIoctl [::]:0 res: {}, error: {}", res_v6, std::io::Error::last_os_error());
}
