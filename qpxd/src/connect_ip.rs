use anyhow::{Context, Result, anyhow};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DARWIN_AF_INET: u32 = 2;
const DARWIN_AF_INET6: u32 = 30;

#[cfg(unix)]
pub(crate) struct SystemIpDevice {
    name: String,
    reader: tokio::fs::File,
    writer: tokio::fs::File,
    framing: DeviceFraming,
}

#[cfg(unix)]
pub(crate) struct IpDeviceReader {
    file: tokio::fs::File,
    framing: DeviceFraming,
}

#[cfg(unix)]
pub(crate) struct IpDeviceWriter {
    file: tokio::fs::File,
    framing: DeviceFraming,
}

#[derive(Clone, Copy)]
#[cfg_attr(
    any(target_os = "macos", target_os = "linux", windows),
    allow(dead_code)
)]
enum DeviceFraming {
    Raw,
    DarwinAddressFamily,
}

#[cfg(unix)]
impl SystemIpDevice {
    pub(crate) fn open(requested_name: Option<&str>, _wintun_dll: Option<&str>) -> Result<Self> {
        let (file, name, framing) = open_platform_device(requested_name)?;
        file.set_nonblocking(true)?;
        let writer = file.try_clone()?;
        Ok(Self {
            name,
            reader: tokio::fs::File::from_std(file),
            writer: tokio::fs::File::from_std(writer),
            framing,
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn split(self) -> (IpDeviceReader, IpDeviceWriter) {
        (
            IpDeviceReader {
                file: self.reader,
                framing: self.framing,
            },
            IpDeviceWriter {
                file: self.writer,
                framing: self.framing,
            },
        )
    }
}

#[cfg(unix)]
impl IpDeviceReader {
    pub(crate) async fn recv_packet(&mut self, buffer: &mut [u8]) -> Result<usize> {
        match self.framing {
            DeviceFraming::Raw => self.file.read(buffer).await.map_err(Into::into),
            DeviceFraming::DarwinAddressFamily => {
                let mut framed = vec![0u8; buffer.len().saturating_add(4)];
                let read = self.file.read(&mut framed).await?;
                decode_device_packet(self.framing, &framed[..read], buffer)
            }
        }
    }
}

#[cfg(unix)]
impl IpDeviceWriter {
    pub(crate) async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        match self.framing {
            DeviceFraming::Raw => self.file.write_all(packet).await?,
            DeviceFraming::DarwinAddressFamily => {
                let framed = encode_device_packet(self.framing, packet)?;
                self.file.write_all(&framed).await?;
            }
        }
        self.file.flush().await?;
        Ok(())
    }
}

fn decode_device_packet(framing: DeviceFraming, framed: &[u8], output: &mut [u8]) -> Result<usize> {
    let payload = match framing {
        DeviceFraming::Raw => framed,
        DeviceFraming::DarwinAddressFamily => {
            if framed.len() < 5 {
                return Err(anyhow!("utun packet is missing its address-family header"));
            }
            let family = u32::from_be_bytes(framed[..4].try_into()?);
            if family != DARWIN_AF_INET && family != DARWIN_AF_INET6 {
                return Err(anyhow!("utun packet has an unsupported address family"));
            }
            &framed[4..]
        }
    };
    if payload.len() > output.len() {
        return Err(anyhow!("network device packet exceeds receive buffer"));
    }
    output[..payload.len()].copy_from_slice(payload);
    Ok(payload.len())
}

fn encode_device_packet(framing: DeviceFraming, packet: &[u8]) -> Result<Vec<u8>> {
    match framing {
        DeviceFraming::Raw => Ok(packet.to_vec()),
        DeviceFraming::DarwinAddressFamily => {
            let family = match packet.first().map(|byte| byte >> 4) {
                Some(4) => DARWIN_AF_INET,
                Some(6) => DARWIN_AF_INET6,
                _ => return Err(anyhow!("utun packet is not IPv4 or IPv6")),
            };
            let mut framed = Vec::with_capacity(packet.len() + 4);
            framed.extend_from_slice(&family.to_be_bytes());
            framed.extend_from_slice(packet);
            Ok(framed)
        }
    }
}

#[cfg(unix)]
trait NonblockingFile {
    fn set_nonblocking(&self, enabled: bool) -> std::io::Result<()>;
}

#[cfg(unix)]
impl NonblockingFile for File {
    fn set_nonblocking(&self, enabled: bool) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: as_raw_fd returns the live descriptor owned by this File.
        let flags = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let next = if enabled {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: the descriptor remains owned and open for the duration of the call.
        if unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, next) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn open_platform_device(requested_name: Option<&str>) -> Result<(File, String, DeviceFraming)> {
    use std::ffi::CStr;
    use std::os::fd::FromRawFd;

    let unit = match requested_name {
        None | Some("auto") => 0,
        Some(name) => name
            .strip_prefix("utun")
            .ok_or_else(|| anyhow!("macOS CONNECT-IP device must be auto or utunN"))?
            .parse::<u32>()?
            .checked_add(1)
            .ok_or_else(|| anyhow!("utun unit overflow"))?,
    };
    // SAFETY: all constants form the documented macOS system-control socket tuple.
    let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create utun control socket");
    }
    let result = (|| -> Result<(File, String, DeviceFraming)> {
        // SAFETY: ctl_info is a plain C structure for which all-zero is a valid input state.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let control_name = b"com.apple.net.utun_control\0";
        if control_name.len() > info.ctl_name.len() {
            return Err(anyhow!("utun control name exceeds ctl_info"));
        }
        for (destination, source) in info.ctl_name.iter_mut().zip(control_name.iter().copied()) {
            *destination = source as libc::c_char;
        }
        // SAFETY: fd is live and info points to writable ctl_info storage.
        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } < 0 {
            return Err(std::io::Error::last_os_error()).context("resolve utun control id");
        }
        let address = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };
        // SAFETY: address has the expected sockaddr_ctl layout and fd is still live.
        if unsafe {
            libc::connect(
                fd,
                (&raw const address).cast::<libc::sockaddr>(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("connect utun device");
        }
        let mut name = [0i8; 64];
        let mut name_len = name.len() as libc::socklen_t;
        // SAFETY: name and name_len provide writable storage for UTUN_OPT_IFNAME.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut name_len,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("read utun interface name");
        }
        // SAFETY: getsockopt returned a NUL-terminated interface name in the fixed buffer.
        let name = unsafe { CStr::from_ptr(name.as_ptr()) }
            .to_str()?
            .to_owned();
        // SAFETY: ownership of the unique live descriptor is transferred to File exactly once.
        let file = unsafe { File::from_raw_fd(fd) };
        Ok((file, name, DeviceFraming::DarwinAddressFamily))
    })();
    if result.is_err() {
        // SAFETY: the error path has not transferred fd ownership to a File.
        unsafe { libc::close(fd) };
    }
    result
}

#[cfg(windows)]
mod wintun {
    use super::*;
    use std::ffi::{c_char, c_void};
    use std::sync::Arc;

    type Adapter = *mut c_void;
    type Session = *mut c_void;
    type Handle = *mut c_void;
    type OpenAdapter = unsafe extern "system" fn(*const u16) -> Adapter;
    type CreateAdapter =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> Adapter;
    type CloseAdapter = unsafe extern "system" fn(Adapter);
    type StartSession = unsafe extern "system" fn(Adapter, u32) -> Session;
    type EndSession = unsafe extern "system" fn(Session);
    type GetReadWaitEvent = unsafe extern "system" fn(Session) -> Handle;
    type ReceivePacket = unsafe extern "system" fn(Session, *mut u32) -> *mut u8;
    type ReleaseReceivePacket = unsafe extern "system" fn(Session, *const u8);
    type AllocateSendPacket = unsafe extern "system" fn(Session, u32) -> *mut u8;
    type SendPacket = unsafe extern "system" fn(Session, *const u8);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(path: *const u16, file: Handle, flags: u32) -> Handle;
        fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
        fn FreeLibrary(module: Handle) -> i32;
        fn GetLastError() -> u32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    }

    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const WAIT_OBJECT_0: u32 = 0;
    const INFINITE: u32 = u32::MAX;

    struct Api {
        module: Handle,
        open_adapter: OpenAdapter,
        create_adapter: CreateAdapter,
        close_adapter: CloseAdapter,
        start_session: StartSession,
        end_session: EndSession,
        get_read_wait_event: GetReadWaitEvent,
        receive_packet: ReceivePacket,
        release_receive_packet: ReleaseReceivePacket,
        allocate_send_packet: AllocateSendPacket,
        send_packet: SendPacket,
    }

    // SAFETY: Api contains an immutable module handle and function pointers from that module.
    unsafe impl Send for Api {}
    // SAFETY: Wintun documents these entry points as callable across threads.
    unsafe impl Sync for Api {}

    impl Api {
        fn load(path: &str) -> Result<Self> {
            let wide = wide(path);
            // SAFETY: wide is NUL-terminated and the flags restrict dependency lookup to safe paths.
            let module = unsafe {
                LoadLibraryExW(
                    wide.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                )
            };
            if module.is_null() {
                return Err(std::io::Error::last_os_error()).context("load Wintun DLL");
            }
            macro_rules! symbol {
                ($name:literal, $ty:ty) => {{
                    // SAFETY: module is live and the symbol name is statically NUL-terminated.
                    let pointer =
                        unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr().cast()) };
                    if pointer.is_null() {
                        // SAFETY: module is owned here and no Api has been constructed.
                        unsafe { FreeLibrary(module) };
                        return Err(anyhow!(concat!("Wintun symbol is missing: ", $name)));
                    }
                    // SAFETY: each symbol is resolved under its official Wintun ABI name and type.
                    unsafe { std::mem::transmute::<*mut c_void, $ty>(pointer) }
                }};
            }
            Ok(Self {
                module,
                open_adapter: symbol!("WintunOpenAdapter", OpenAdapter),
                create_adapter: symbol!("WintunCreateAdapter", CreateAdapter),
                close_adapter: symbol!("WintunCloseAdapter", CloseAdapter),
                start_session: symbol!("WintunStartSession", StartSession),
                end_session: symbol!("WintunEndSession", EndSession),
                get_read_wait_event: symbol!("WintunGetReadWaitEvent", GetReadWaitEvent),
                receive_packet: symbol!("WintunReceivePacket", ReceivePacket),
                release_receive_packet: symbol!("WintunReleaseReceivePacket", ReleaseReceivePacket),
                allocate_send_packet: symbol!("WintunAllocateSendPacket", AllocateSendPacket),
                send_packet: symbol!("WintunSendPacket", SendPacket),
            })
        }
    }

    struct Inner {
        api: Api,
        adapter: Adapter,
        session: Session,
    }

    // SAFETY: Wintun adapter and session handles support concurrent reader/writer access.
    unsafe impl Send for Inner {}
    // SAFETY: lifetime is synchronized by Arc and destruction occurs after the final reference.
    unsafe impl Sync for Inner {}

    impl Drop for Inner {
        fn drop(&mut self) {
            // SAFETY: Inner uniquely owns the live session, adapter, and module in this order.
            unsafe {
                (self.api.end_session)(self.session);
                (self.api.close_adapter)(self.adapter);
                FreeLibrary(self.api.module);
            }
        }
    }

    pub(crate) struct SystemIpDevice {
        name: String,
        inner: Arc<Inner>,
    }

    pub(crate) struct IpDeviceReader(Arc<Inner>);
    pub(crate) struct IpDeviceWriter(Arc<Inner>);

    impl SystemIpDevice {
        pub(crate) fn open(name: Option<&str>, dll: Option<&str>) -> Result<Self> {
            let name = name.ok_or_else(|| anyhow!("Wintun adapter name is required"))?;
            let dll = dll.ok_or_else(|| anyhow!("absolute wintun_dll path is required"))?;
            let api = Api::load(dll)?;
            let wide_name = wide(name);
            // SAFETY: wide_name is NUL-terminated and api remains loaded for the call.
            let mut adapter = unsafe { (api.open_adapter)(wide_name.as_ptr()) };
            if adapter.is_null() {
                let tunnel_type = wide("qpx");
                // SAFETY: both UTF-16 strings are NUL-terminated and a null GUID is permitted.
                adapter = unsafe {
                    (api.create_adapter)(wide_name.as_ptr(), tunnel_type.as_ptr(), std::ptr::null())
                };
            }
            if adapter.is_null() {
                // SAFETY: no adapter/session owns the module on this error path.
                unsafe { FreeLibrary(api.module) };
                return Err(std::io::Error::last_os_error()).context("open Wintun adapter");
            }
            // SAFETY: adapter is live and the ring capacity satisfies the Wintun API contract.
            let session = unsafe { (api.start_session)(adapter, 4 * 1024 * 1024) };
            if session.is_null() {
                // SAFETY: this path uniquely owns adapter and module and no session was created.
                unsafe {
                    (api.close_adapter)(adapter);
                    FreeLibrary(api.module);
                }
                return Err(std::io::Error::last_os_error()).context("start Wintun session");
            }
            Ok(Self {
                name: name.to_owned(),
                inner: Arc::new(Inner {
                    api,
                    adapter,
                    session,
                }),
            })
        }

        pub(crate) fn name(&self) -> &str {
            &self.name
        }

        pub(crate) fn split(self) -> (IpDeviceReader, IpDeviceWriter) {
            (
                IpDeviceReader(self.inner.clone()),
                IpDeviceWriter(self.inner),
            )
        }
    }

    impl IpDeviceReader {
        pub(crate) async fn recv_packet(&mut self, output: &mut [u8]) -> Result<usize> {
            let inner = self.0.clone();
            let packet = tokio::task::spawn_blocking(move || receive(&inner)).await??;
            if packet.len() > output.len() {
                return Err(anyhow!("Wintun packet exceeds receive buffer"));
            }
            output[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    impl IpDeviceWriter {
        pub(crate) async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
            let inner = self.0.clone();
            let packet = packet.to_vec();
            tokio::task::spawn_blocking(move || send(&inner, &packet)).await??;
            Ok(())
        }
    }

    fn receive(inner: &Inner) -> Result<Vec<u8>> {
        loop {
            let mut size = 0u32;
            // SAFETY: session is live and size points to writable storage for the packet length.
            let packet = unsafe { (inner.api.receive_packet)(inner.session, &mut size) };
            if !packet.is_null() {
                // SAFETY: Wintun returned packet with exactly size readable bytes.
                let bytes = unsafe { std::slice::from_raw_parts(packet, size as usize) }.to_vec();
                // SAFETY: packet belongs to this session and is released exactly once after copying.
                unsafe { (inner.api.release_receive_packet)(inner.session, packet) };
                return Ok(bytes);
            }
            // SAFETY: GetLastError has no pointer preconditions and is read immediately after failure.
            if unsafe { GetLastError() } != ERROR_NO_MORE_ITEMS {
                return Err(std::io::Error::last_os_error()).context("receive Wintun packet");
            }
            // SAFETY: session is live and owns its read-wait event.
            let event = unsafe { (inner.api.get_read_wait_event)(inner.session) };
            // SAFETY: non-null event remains live while the session Arc is held.
            if event.is_null() || unsafe { WaitForSingleObject(event, INFINITE) } != WAIT_OBJECT_0 {
                return Err(std::io::Error::last_os_error()).context("wait for Wintun packet");
            }
        }
    }

    fn send(inner: &Inner, packet: &[u8]) -> Result<()> {
        let size = u32::try_from(packet.len())?;
        // SAFETY: session is live and size was checked to fit the Wintun API integer width.
        let target = unsafe { (inner.api.allocate_send_packet)(inner.session, size) };
        if target.is_null() {
            return Err(std::io::Error::last_os_error()).context("allocate Wintun packet");
        }
        // SAFETY: target has packet.len() writable bytes and is transferred once to Wintun.
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), target, packet.len());
            (inner.api.send_packet)(inner.session, target);
        }
        Ok(())
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(windows)]
pub(crate) use wintun::SystemIpDevice;

#[cfg(target_os = "linux")]
fn open_platform_device(requested_name: Option<&str>) -> Result<(File, String, DeviceFraming)> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .context("open /dev/net/tun")?;
    let requested = requested_name.unwrap_or("qpx%d");
    if requested.is_empty() || requested.len() >= libc::IFNAMSIZ {
        return Err(anyhow!("Linux CONNECT-IP interface name is invalid"));
    }
    let mut request = [0u8; 40];
    request[..requested.len()].copy_from_slice(requested.as_bytes());
    request[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    // SAFETY: file is a live /dev/net/tun descriptor and request matches Linux ifreq layout.
    if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, request.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error()).context("create Linux TUN device");
    }
    let name_len = request[..libc::IFNAMSIZ]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(libc::IFNAMSIZ);
    let name = std::str::from_utf8(&request[..name_len])?.to_owned();
    Ok((file, name, DeviceFraming::Raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_framing_round_trips_ipv4_and_ipv6() {
        for packet in [vec![0x45, 0, 0, 20], vec![0x60, 0, 0, 0]] {
            for framing in [DeviceFraming::Raw, DeviceFraming::DarwinAddressFamily] {
                let encoded = encode_device_packet(framing, &packet).unwrap();
                let mut decoded = [0u8; 64];
                let len = decode_device_packet(framing, &encoded, &mut decoded).unwrap();
                assert_eq!(&decoded[..len], packet.as_slice());
            }
        }
    }

    #[test]
    fn device_framing_rejects_non_ip_and_unknown_darwin_family() {
        assert!(encode_device_packet(DeviceFraming::DarwinAddressFamily, &[0]).is_err());
        assert!(
            decode_device_packet(
                DeviceFraming::DarwinAddressFamily,
                &[0, 0, 0, 99, 0x45],
                &mut [0u8; 8],
            )
            .is_err()
        );
    }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn open_platform_device(_requested_name: Option<&str>) -> Result<(File, String, DeviceFraming)> {
    Err(anyhow!(
        "CONNECT-IP has no network device backend on this OS"
    ))
}
