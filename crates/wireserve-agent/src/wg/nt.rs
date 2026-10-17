//! WireGuard on Windows: wireguard-nt, through `wireguard.dll`'s own C
//! API, offering `WgInterface` the same five calls defguard's
//! `WGApi<Kernel>` does on Linux.
//!
//! Neither existing wrapper will do. defguard's Windows backend makes
//! `configure_peer` and `remove_peer` no-ops, loads the DLL from a path
//! relative to the working directory (a service's is `System32`), and
//! routes every `AllowedIPs` entry itself. The `wireguard-nt` crate's only
//! configuration call replaces every peer, which drops every session and
//! the endpoint roaming `peers_to_configure` exists to keep (security
//! review F6). The API itself has what is needed: per-peer add, update and
//! remove in one `WireGuardSetConfiguration` call.
//!
//! An adapter lives exactly as long as the handle that created it:
//! closing it, including by the process dying, removes the adapter with
//! its addresses and routes. A crashed agent therefore leaves no tunnel
//! behind on Windows, rather than a configured one as on Linux. Removal
//! finishes a moment after the handle closes (Plug and Play takes the
//! device away asynchronously), so an adapter of our name that is still
//! listed is either on its way out or another process's — never one to
//! adopt: [`NtApi::create_interface`] waits for it to go instead.
//!
//! `wireguard.dll` is loaded from the directory the executable is in and
//! nowhere else, so nothing on `PATH` or in the working directory can
//! stand in for it.

use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use defguard_wireguard_rs::error::WireguardInterfaceError;
use defguard_wireguard_rs::host::Host;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::InterfaceConfiguration;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NOT_FOUND};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, SOCKADDR_INET};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR};

use crate::winnet;

/// What the adapters are listed as in Windows ("WireServe Tunnel").
const TUNNEL_TYPE: &str = "WireServe";

/// How long a closed adapter may take to disappear.
pub(crate) const REMOVAL_WAIT: Duration = Duration::from_secs(5);

// ---- wireguard.h ----

type AdapterHandle = *mut c_void;

const INTERFACE_HAS_PRIVATE_KEY: i32 = 1 << 1;
const INTERFACE_HAS_LISTEN_PORT: i32 = 1 << 2;
const INTERFACE_REPLACE_PEERS: i32 = 1 << 3;

const PEER_HAS_PUBLIC_KEY: i32 = 1 << 0;
const PEER_HAS_PRESHARED_KEY: i32 = 1 << 1;
const PEER_HAS_PERSISTENT_KEEPALIVE: i32 = 1 << 2;
const PEER_HAS_ENDPOINT: i32 = 1 << 3;
const PEER_REPLACE_ALLOWED_IPS: i32 = 1 << 5;
const PEER_REMOVE: i32 = 1 << 6;

const ADAPTER_STATE_UP: i32 = 1;

// The layouts are wireguard-nt 1.1's `wireguard.h`. The padding the C
// compiler puts into these structs is spelled out as fields here, and
// always zero: `ConfigBuf::push` copies a struct out as whole words, and
// implicit padding is uninitialized memory. It was once, and it cost real
// allowed IPs: what 0.10 left as padding after an allowed IP's prefix
// length, 1.x reads as that allowed IP's flags, and the driver is shared
// by every wireguard-nt user on the host — so a 1.x driver, there from
// another WireGuard install, removed the allowed IPs garbage told it to.

/// `WIREGUARD_INTERFACE`, followed in memory by `peers_count` peers.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct NtInterface {
    flags: i32,
    listen_port: u16,
    private_key: [u8; 32],
    public_key: [u8; 32],
    _pad0: [u8; 2],
    peers_count: u32,
    _pad1: u32,
}

impl NtInterface {
    fn new(flags: i32, listen_port: u16, private_key: [u8; 32], peers_count: u32) -> Self {
        Self { flags, listen_port, private_key, public_key: [0; 32], _pad0: [0; 2], peers_count, _pad1: 0 }
    }
}

/// `WIREGUARD_PEER`, followed in memory by `allowed_ips_count` allowed IPs.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct NtPeer {
    flags: i32,
    reserved: u32,
    public_key: [u8; 32],
    preshared_key: [u8; 32],
    persistent_keepalive: u16,
    _pad0: [u8; 2],
    endpoint: SOCKADDR_INET,
    tx_bytes: u64,
    rx_bytes: u64,
    /// 100 ns intervals since 1601-01-01 UTC; 0 for never.
    last_handshake: u64,
    allowed_ips_count: u32,
    _pad1: u32,
}

/// `WIREGUARD_ALLOWED_IP`: an `IN_ADDR`/`IN6_ADDR` union, its family and
/// prefix length, and flags. The one flag, `WIREGUARD_ALLOWED_IP_REMOVE`
/// (remove this allowed IP rather than add it), is never used here:
/// a peer's allowed IPs are always replaced whole.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct NtAllowedIp {
    address: [u8; 16],
    family: ADDRESS_FAMILY,
    cidr: u8,
    _pad: u8,
    flags: i32,
}

// The layout wireguard.h has: every size a multiple of 8 (which
// `ConfigBuf` relies on), and no byte left to padding the explicit fields
// don't cover.
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<NtInterface>() == 80);
    assert!(offset_of!(NtInterface, listen_port) == 4 && offset_of!(NtInterface, private_key) == 6);
    assert!(offset_of!(NtInterface, peers_count) == 72);
    assert!(size_of::<NtPeer>() == 136);
    assert!(offset_of!(NtPeer, persistent_keepalive) == 72 && offset_of!(NtPeer, endpoint) == 76);
    assert!(offset_of!(NtPeer, tx_bytes) == 104 && offset_of!(NtPeer, allowed_ips_count) == 128);
    assert!(size_of::<NtAllowedIp>() == 24);
    assert!(offset_of!(NtAllowedIp, family) == 16 && offset_of!(NtAllowedIp, cidr) == 18);
    assert!(offset_of!(NtAllowedIp, flags) == 20);
    // The fields' own sizes add up to the whole: no implicit padding anywhere.
    let key = size_of::<[u8; 32]>();
    assert!(size_of::<i32>() + size_of::<u16>() + 2 * key + size_of::<[u8; 2]>() + 2 * size_of::<u32>() == 80);
    assert!(
        size_of::<i32>() + size_of::<u32>() + 2 * key + size_of::<u16>() + size_of::<[u8; 2]>()
            + size_of::<SOCKADDR_INET>() + 3 * size_of::<u64>() + 2 * size_of::<u32>()
            == 136
    );
    assert!(size_of::<[u8; 16]>() + size_of::<ADDRESS_FAMILY>() + 2 * size_of::<u8>() + size_of::<i32>() == 24);
};

type CreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> AdapterHandle;
type OpenAdapter = unsafe extern "system" fn(*const u16) -> AdapterHandle;
type CloseAdapter = unsafe extern "system" fn(AdapterHandle);
type GetAdapterLuid = unsafe extern "system" fn(AdapterHandle, *mut NET_LUID_LH);
type SetAdapterState = unsafe extern "system" fn(AdapterHandle, i32) -> i32;
type SetConfiguration = unsafe extern "system" fn(AdapterHandle, *const NtInterface, u32) -> i32;
type GetConfiguration = unsafe extern "system" fn(AdapterHandle, *mut NtInterface, *mut u32) -> i32;

struct Dll {
    create_adapter: CreateAdapter,
    open_adapter: OpenAdapter,
    close_adapter: CloseAdapter,
    get_adapter_luid: GetAdapterLuid,
    set_adapter_state: SetAdapterState,
    set_configuration: SetConfiguration,
    get_configuration: GetConfiguration,
}

fn dll() -> io::Result<&'static Dll> {
    static DLL: OnceLock<Result<Dll, String>> = OnceLock::new();
    DLL.get_or_init(|| load().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| io::Error::other(format!("could not load wireguard.dll from the executable's directory: {e}")))
}

fn load() -> io::Result<Dll> {
    let name = winnet::wide("wireguard.dll");
    // SAFETY: a NUL-terminated name; the search is limited to the
    // application's own directory. The module is never freed: `Dll`'s
    // function pointers live for the rest of the process.
    let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_APPLICATION_DIR) };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    macro_rules! symbol {
        ($name:literal as $ty:ty) => {{
            // SAFETY: a NUL-terminated ASCII name, looked up in a loaded module.
            let f = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }
                .ok_or_else(|| io::Error::other(concat!("wireguard.dll has no ", $name)))?;
            // SAFETY: `$ty` is the signature wireguard.h declares for this name.
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f) }
        }};
    }
    Ok(Dll {
        create_adapter: symbol!("WireGuardCreateAdapter" as CreateAdapter),
        open_adapter: symbol!("WireGuardOpenAdapter" as OpenAdapter),
        close_adapter: symbol!("WireGuardCloseAdapter" as CloseAdapter),
        get_adapter_luid: symbol!("WireGuardGetAdapterLUID" as GetAdapterLuid),
        set_adapter_state: symbol!("WireGuardSetAdapterState" as SetAdapterState),
        set_configuration: symbol!("WireGuardSetConfiguration" as SetConfiguration),
        get_configuration: symbol!("WireGuardGetConfiguration" as GetConfiguration),
    })
}

fn last_error() -> io::Error {
    // SAFETY: reads the calling thread's last-error value.
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

/// An open adapter handle. Dropping it closes the handle, which removes
/// the adapter when this handle is the one that created it.
struct Adapter {
    handle: AdapterHandle,
}

// SAFETY: wireguard-nt handles may be used from any thread.
unsafe impl Send for Adapter {}

impl Drop for Adapter {
    fn drop(&mut self) {
        if let Ok(dll) = dll() {
            // SAFETY: a handle we own, closed exactly once.
            unsafe { (dll.close_adapter)(self.handle) };
        }
    }
}

impl Adapter {
    /// The existing adapter called `name`, if there is one.
    fn open(name: &str) -> io::Result<Option<Self>> {
        let dll = dll()?;
        let name = winnet::wide(name);
        // SAFETY: a NUL-terminated name.
        let handle = unsafe { (dll.open_adapter)(name.as_ptr()) };
        if handle.is_null() {
            let err = last_error();
            // "Not found" comes back as either of these, depending on how far
            // the lookup got.
            let code = err.raw_os_error();
            return if code == Some(ERROR_FILE_NOT_FOUND as i32) || code == Some(ERROR_NOT_FOUND as i32) {
                Ok(None)
            } else {
                Err(err)
            };
        }
        Ok(Some(Self { handle }))
    }

    fn create(name: &str) -> io::Result<Self> {
        let dll = dll()?;
        let wide_name = winnet::wide(name);
        let tunnel_type = winnet::wide(TUNNEL_TYPE);
        let guid = adapter_guid(name);
        // SAFETY: NUL-terminated strings and a GUID that outlive the call.
        let handle = unsafe { (dll.create_adapter)(wide_name.as_ptr(), tunnel_type.as_ptr(), &guid) };
        if handle.is_null() {
            return Err(last_error());
        }
        Ok(Self { handle })
    }

    fn luid(&self) -> io::Result<NET_LUID_LH> {
        let dll = dll()?;
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: a live handle; `luid` is written by the call.
        unsafe { (dll.get_adapter_luid)(self.handle, &mut luid) };
        Ok(luid)
    }

    fn set_up(&self) -> io::Result<()> {
        let dll = dll()?;
        // SAFETY: a live handle.
        if unsafe { (dll.set_adapter_state)(self.handle, ADAPTER_STATE_UP) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    fn set_config(&self, buf: &ConfigBuf) -> io::Result<()> {
        let dll = dll()?;
        // SAFETY: `buf` holds a complete, 8-aligned WIREGUARD_INTERFACE with
        // its peers and their allowed IPs, `bytes` long.
        let ok = unsafe { (dll.set_configuration)(self.handle, buf.words.as_ptr().cast(), buf.bytes()) };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    fn get_config(&self) -> io::Result<Vec<u64>> {
        let dll = dll()?;
        let mut bytes = (std::mem::size_of::<NtInterface>() + 16 * std::mem::size_of::<NtPeer>()) as u32;
        loop {
            let mut words = vec![0u64; (bytes as usize).div_ceil(8)];
            // SAFETY: `words` is `bytes` long and 8-aligned; on ERROR_MORE_DATA
            // the call writes the size it needs to `bytes`.
            let ok = unsafe { (dll.get_configuration)(self.handle, words.as_mut_ptr().cast(), &mut bytes) };
            if ok != 0 {
                words.truncate((bytes as usize).div_ceil(8));
                return Ok(words);
            }
            let err = last_error();
            if err.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
                return Err(err);
            }
        }
    }
}

/// The adapter GUID for `name`: the same one every time, so Windows sees
/// the same network on every start instead of adding "Network 2", "3", …
/// to its list, each with its own firewall profile. Two FNV-1a hashes of
/// the name; nothing about it needs to be secret or unguessable.
fn adapter_guid(name: &str) -> GUID {
    let fnv = |seed: u64| {
        name.bytes()
            .fold(seed, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
    };
    let (a, b) = (fnv(0xcbf2_9ce4_8422_2325), fnv(0x84222325_cbf29ce4));
    GUID::from_u128((u128::from(a) << 64) | u128::from(b))
}

/// A `WIREGUARD_INTERFACE` with its peers being written out, in a buffer
/// of `u64`s so it has the 8-byte alignment wireguard-nt expects.
struct ConfigBuf {
    words: Vec<u64>,
}

impl ConfigBuf {
    fn new(interface: NtInterface) -> Self {
        let mut buf = Self { words: Vec::new() };
        buf.push(&interface);
        buf
    }

    fn push<T: Copy>(&mut self, value: &T) {
        const { assert!(std::mem::size_of::<T>().is_multiple_of(8) && std::mem::align_of::<T>() == 8) };
        // SAFETY: `T` is plain data whose size is a whole number of words.
        let words = unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u64>(), std::mem::size_of::<T>() / 8)
        };
        self.words.extend_from_slice(words);
    }

    fn push_peer(&mut self, peer: &Peer, flags: i32) {
        let mut flags = flags | PEER_HAS_PUBLIC_KEY;
        let mut nt = NtPeer {
            flags: 0,
            reserved: 0,
            public_key: peer.public_key.as_array(),
            preshared_key: [0; 32],
            persistent_keepalive: 0,
            _pad0: [0; 2],
            // SAFETY: all-zero is AF_UNSPEC.
            endpoint: unsafe { std::mem::zeroed() },
            tx_bytes: 0,
            rx_bytes: 0,
            last_handshake: 0,
            allowed_ips_count: 0,
            _pad1: 0,
        };
        if flags & PEER_REMOVE == 0 {
            // Always sent, so going back to none (0) is applied too.
            flags |= PEER_HAS_PERSISTENT_KEEPALIVE | PEER_REPLACE_ALLOWED_IPS;
            nt.persistent_keepalive = peer.persistent_keepalive_interval.unwrap_or(0);
            if let Some(psk) = &peer.preshared_key {
                flags |= PEER_HAS_PRESHARED_KEY;
                nt.preshared_key = psk.as_array();
            }
            if let Some(endpoint) = peer.endpoint {
                flags |= PEER_HAS_ENDPOINT;
                nt.endpoint = winnet::to_sockaddr_inet(endpoint);
            }
            nt.allowed_ips_count = peer.allowed_ips.len() as u32;
        }
        nt.flags = flags;
        self.push(&nt);
        if flags & PEER_REMOVE == 0 {
            for ip in &peer.allowed_ips {
                self.push(&allowed_ip(ip));
            }
        }
    }

    fn set_peers_count(&mut self, count: u32) {
        // SAFETY: the buffer starts with the interface struct `new` wrote.
        unsafe { (*self.words.as_mut_ptr().cast::<NtInterface>()).peers_count = count };
    }

    fn bytes(&self) -> u32 {
        (self.words.len() * 8) as u32
    }
}

fn allowed_ip(ip: &IpAddrMask) -> NtAllowedIp {
    let mut address = [0u8; 16];
    let family = match ip.address {
        IpAddr::V4(a) => {
            address[..4].copy_from_slice(&a.octets());
            AF_INET
        }
        IpAddr::V6(a) => {
            address.copy_from_slice(&a.octets());
            AF_INET6
        }
    };
    NtAllowedIp { address, family, cidr: ip.cidr, _pad: 0, flags: 0 }
}

/// Reads a `WIREGUARD_INTERFACE` with its peers, as `get_config` returns it.
fn parse_config(words: &[u64]) -> io::Result<Host> {
    let bytes: &[u8] =
        // SAFETY: viewing initialized `u64`s as bytes.
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), words.len() * 8) };
    let mut offset = 0;
    let interface: NtInterface = read(bytes, &mut offset)?;
    let mut host = Host::new(interface.listen_port, Key::new(interface.private_key));
    if interface.flags & INTERFACE_HAS_PRIVATE_KEY == 0 {
        host.private_key = None;
    }
    for _ in 0..interface.peers_count {
        let nt: NtPeer = read(bytes, &mut offset)?;
        let mut peer = Peer::new(Key::new(nt.public_key));
        if nt.flags & PEER_HAS_PRESHARED_KEY != 0 {
            peer.preshared_key = Some(Key::new(nt.preshared_key));
        }
        if nt.flags & PEER_HAS_ENDPOINT != 0 {
            peer.endpoint = winnet::from_sockaddr_inet(&nt.endpoint);
        }
        if nt.flags & PEER_HAS_PERSISTENT_KEEPALIVE != 0 && nt.persistent_keepalive != 0 {
            peer.persistent_keepalive_interval = Some(nt.persistent_keepalive);
        }
        peer.tx_bytes = nt.tx_bytes;
        peer.rx_bytes = nt.rx_bytes;
        peer.last_handshake = filetime(nt.last_handshake);
        for _ in 0..nt.allowed_ips_count {
            let ip: NtAllowedIp = read(bytes, &mut offset)?;
            let address = if ip.family == AF_INET6 {
                IpAddr::V6(Ipv6Addr::from(ip.address))
            } else {
                IpAddr::V4(Ipv4Addr::new(ip.address[0], ip.address[1], ip.address[2], ip.address[3]))
            };
            peer.allowed_ips.push(IpAddrMask::new(address, ip.cidr));
        }
        host.peers.insert(peer.public_key.clone(), peer);
    }
    Ok(host)
}

fn read<T: Copy>(bytes: &[u8], offset: &mut usize) -> io::Result<T> {
    let end = *offset + std::mem::size_of::<T>();
    if end > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wireguard-nt returned a truncated configuration"));
    }
    // SAFETY: in bounds; `T` is plain data, read without assuming alignment.
    let value = unsafe { bytes.as_ptr().add(*offset).cast::<T>().read_unaligned() };
    *offset = end;
    Ok(value)
}

/// A Windows FILETIME (100 ns since 1601) as a `SystemTime`; 0 is "never".
fn filetime(ft: u64) -> Option<SystemTime> {
    const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
    let since_unix = ft.checked_sub(UNIX_EPOCH_AS_FILETIME).filter(|_| ft != 0)?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_nanos(since_unix.saturating_mul(100)))
}

/// Whether no adapter is listed as `name`, now or within `wait`.
pub(crate) fn gone_within(name: &str, wait: Duration) -> bool {
    let deadline = std::time::Instant::now() + wait;
    loop {
        if matches!(winnet::luid_by_alias(name), Ok(None)) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wg_err(e: io::Error) -> WireguardInterfaceError {
    WireguardInterfaceError::IoError(e)
}

/// The Windows counterpart of `WGApi<Kernel>`, with the calls `WgInterface`
/// makes of it.
pub struct NtApi {
    ifname: String,
    adapter: Option<Adapter>,
}

impl NtApi {
    pub fn new(ifname: String) -> Result<Self, WireguardInterfaceError> {
        Ok(Self { ifname, adapter: None })
    }

    fn adapter(&self) -> Result<&Adapter, WireguardInterfaceError> {
        self.adapter
            .as_ref()
            .ok_or_else(|| WireguardInterfaceError::Interface(format!("{} has not been created", self.ifname)))
    }

    /// Creates the adapter. One already listed under the name — this
    /// agent's own from a moment ago, still being removed, or another
    /// process's — is waited out rather than adopted: a handle opened on a
    /// dying adapter would go dead under us, and another process's isn't
    /// ours to configure.
    pub fn create_interface(&mut self) -> Result<(), WireguardInterfaceError> {
        if self.adapter.is_some() {
            return Ok(());
        }
        if !gone_within(&self.ifname, REMOVAL_WAIT) {
            return Err(WireguardInterfaceError::Interface(format!(
                "an adapter named {} exists and is held by another process",
                self.ifname
            )));
        }
        self.adapter = Some(Adapter::create(&self.ifname).map_err(wg_err)?);
        Ok(())
    }

    /// The private key, listen port, peers, addresses and MTU, then up —
    /// what defguard's `configure_interface` does on Linux. Like there, it
    /// replaces every peer.
    pub fn configure_interface(&self, config: &InterfaceConfiguration) -> Result<(), WireguardInterfaceError> {
        let adapter = self.adapter()?;
        let private_key = Key::try_from(config.prvkey.as_str()).map_err(|_| {
            WireguardInterfaceError::Interface("the private key is not a valid WireGuard key".to_string())
        })?;
        let mut buf = ConfigBuf::new(NtInterface::new(
            INTERFACE_HAS_PRIVATE_KEY | INTERFACE_HAS_LISTEN_PORT | INTERFACE_REPLACE_PEERS,
            config.port,
            private_key.as_array(),
            0,
        ));
        for peer in &config.peers {
            buf.push_peer(peer, 0);
        }
        buf.set_peers_count(config.peers.len() as u32);
        adapter.set_config(&buf).map_err(wg_err)?;

        let luid = adapter.luid().map_err(wg_err)?;
        let addrs: Vec<(IpAddr, u8)> = config.addresses.iter().map(|a| (a.address, a.cidr)).collect();
        winnet::set_addresses(luid, &addrs).map_err(wg_err)?;
        if let Some(mtu) = config.mtu {
            winnet::set_mtu(luid, mtu).map_err(wg_err)?;
        }
        adapter.set_up().map_err(wg_err)
    }

    /// Adds `peer`, or updates it in place: its endpoint, keepalive and
    /// allowed IPs change, its session and roaming state stay.
    pub fn configure_peer(&self, peer: &Peer) -> Result<(), WireguardInterfaceError> {
        self.set_one_peer(peer, 0)
    }

    pub fn remove_peer(&self, key: &Key) -> Result<(), WireguardInterfaceError> {
        self.set_one_peer(&Peer::new(key.clone()), PEER_REMOVE)
    }

    fn set_one_peer(&self, peer: &Peer, flags: i32) -> Result<(), WireguardInterfaceError> {
        let mut buf = ConfigBuf::new(NtInterface::new(0, 0, [0; 32], 1));
        buf.push_peer(peer, flags);
        self.adapter()?.set_config(&buf).map_err(wg_err)
    }

    /// The adapter's configuration and peers, through this API's own handle
    /// or, before `create_interface`, a handle opened just for this.
    pub fn read_interface_data(&self) -> Result<Host, WireguardInterfaceError> {
        let opened;
        let adapter = match &self.adapter {
            Some(adapter) => adapter,
            None => {
                opened = Adapter::open(&self.ifname)
                    .map_err(wg_err)?
                    .ok_or_else(|| WireguardInterfaceError::Interface(format!("there is no adapter {}", self.ifname)))?;
                &opened
            }
        };
        let words = adapter.get_config().map_err(wg_err)?;
        parse_config(&words).map_err(wg_err)
    }

    /// Closes this API's handle, which removes the adapter if this handle
    /// created it, and waits for it to be gone — so what runs next, a
    /// restart included, never meets it half-removed.
    pub fn remove_interface(&mut self) {
        if self.adapter.take().is_some() && !gone_within(&self.ifname, REMOVAL_WAIT) {
            tracing::warn!(ifname = %self.ifname, "the adapter is still listed after its handle closed");
        }
    }

    /// The adapter's LUID, once `create_interface` has run.
    pub fn luid(&self) -> Option<NET_LUID_LH> {
        self.adapter.as_ref().and_then(|a| a.luid().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> Peer {
        let mut p = Peer::new(Key::new([byte; 32]));
        p.endpoint = Some("198.51.100.7:51820".parse().unwrap());
        p.persistent_keepalive_interval = Some(25);
        p.allowed_ips = vec![
            IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(100, 90, 0, byte)), 32),
            IpAddrMask::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(byte))), 128),
        ];
        p
    }

    /// What wireguard-nt would hand back for the configuration we send:
    /// the same layout, read by the same parser.
    #[test]
    fn a_written_configuration_reads_back_the_same() {
        let mut buf =
            ConfigBuf::new(NtInterface::new(INTERFACE_HAS_PRIVATE_KEY | INTERFACE_HAS_LISTEN_PORT, 51820, [9; 32], 0));
        let (a, mut b) = (peer(1), peer(2));
        b.endpoint = None;
        b.persistent_keepalive_interval = None;
        buf.push_peer(&a, 0);
        buf.push_peer(&b, 0);
        buf.set_peers_count(2);
        assert_eq!(buf.bytes() as usize, 80 + 2 * (136 + 2 * 24));

        let host = parse_config(&buf.words).unwrap();
        assert_eq!(host.listen_port, 51820);
        assert_eq!(host.private_key, Some(Key::new([9; 32])));
        assert_eq!(host.peers[&a.public_key].endpoint, a.endpoint);
        assert_eq!(host.peers[&a.public_key].allowed_ips, a.allowed_ips);
        assert_eq!(host.peers[&a.public_key].persistent_keepalive_interval, Some(25));
        assert_eq!(host.peers[&b.public_key].endpoint, None);
        assert_eq!(host.peers[&b.public_key].persistent_keepalive_interval, None);
    }

    #[test]
    fn a_removal_carries_only_the_key() {
        let mut buf = ConfigBuf::new(NtInterface::new(0, 0, [0; 32], 1));
        buf.push_peer(&peer(3), PEER_REMOVE);
        assert_eq!(buf.bytes(), 80 + 136);
        let nt: NtPeer = read(
            unsafe { std::slice::from_raw_parts(buf.words.as_ptr().cast(), buf.words.len() * 8) },
            &mut 80,
        )
        .unwrap();
        assert_eq!(nt.flags, PEER_HAS_PUBLIC_KEY | PEER_REMOVE);
        assert_eq!(nt.allowed_ips_count, 0);
    }

    #[test]
    fn a_truncated_configuration_is_an_error_not_a_crash() {
        let buf = ConfigBuf::new(NtInterface::new(0, 0, [0; 32], 3));
        assert!(parse_config(&buf.words).is_err());
    }

    #[test]
    fn handshake_times_convert_from_filetime() {
        assert_eq!(filetime(0), None);
        assert_eq!(filetime(116_444_736_000_000_000 + 10_000_000), Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1)));
    }

    /// Against the real driver: an adapter comes up with its addresses,
    /// takes peers one at a time — each change leaving the others as they
    /// were — routes to them, and is gone when its handle closes. Needs
    /// `wireguard.dll` next to the test binary and an elevated run.
    #[test]
    fn kernel_an_adapter_takes_peers_one_at_a_time_and_goes_away_with_its_handle() {
        let skip = |why: &str| {
            assert!(std::env::var_os("WIRESERVE_TEST_STRICT").is_none(), "would skip under WIRESERVE_TEST_STRICT: {why}");
            eprintln!("SKIPPED: {why}");
        };
        if let Err(e) = dll() {
            return skip(&e.to_string());
        }
        if !crate::winsec::is_elevated().unwrap_or(false) {
            return skip("not elevated: creating an adapter takes an administrator");
        }
        let name = format!("wstest{}", std::process::id() % 100_000);
        let mut api = NtApi::new(name.clone()).unwrap();
        api.create_interface().unwrap();
        let own = Key::new([0x11; 32]);
        api.configure_interface(&InterfaceConfiguration {
            name: name.clone(),
            prvkey: own.to_string(),
            addresses: vec![IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(100, 64, 250, 1)), 32)],
            port: 0,
            peers: Vec::new(),
            mtu: Some(1420),
            fwmark: None,
        })
        .unwrap();
        assert!(winnet::luid_by_alias(&name).unwrap().is_some(), "the adapter is listed under its name");
        assert!(winnet::host_addresses()
            .unwrap()
            .iter()
            .any(|a| a.ifname == name && a.addr == IpAddr::V4(Ipv4Addr::new(100, 64, 250, 1))));

        // What the driver reports, after each step, for when this fails.
        let show = |step: &str, host: &Host| {
            let mut peers: Vec<_> = host.peers.values().map(|p| (p.public_key.as_array()[0], &p.allowed_ips)).collect();
            peers.sort_by_key(|p| p.0);
            eprintln!("after {step}: {peers:?}");
        };
        let (mut a, mut b) = (peer(2), peer(3));
        b.endpoint = None;
        api.configure_peer(&a).unwrap();
        let host = api.read_interface_data().unwrap();
        show("adding a", &host);
        assert_eq!(host.peers[&a.public_key].allowed_ips, a.allowed_ips);
        api.configure_peer(&b).unwrap();
        let host = api.read_interface_data().unwrap();
        show("adding b", &host);
        assert_eq!(host.peers.len(), 2);
        assert!(host.private_key.is_some());
        assert_eq!(host.peers[&a.public_key].endpoint, a.endpoint);
        assert_eq!(host.peers[&b.public_key].endpoint, None);

        // Updating one peer replaces its allowed IPs and leaves the other's.
        a.allowed_ips = vec![IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(100, 64, 250, 9)), 32)];
        api.configure_peer(&a).unwrap();
        let host = api.read_interface_data().unwrap();
        show("updating a", &host);
        assert_eq!(host.peers[&a.public_key].allowed_ips, a.allowed_ips);
        assert_eq!(host.peers[&b.public_key].allowed_ips, b.allowed_ips);

        // An address moving from one peer to another — a service address
        // changing owner — and the old owner then updated: each keeps
        // exactly what it was last given.
        let moved = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(100, 64, 250, 9)), 32);
        b.allowed_ips.push(moved.clone());
        api.configure_peer(&b).unwrap();
        show("moving an address to b", &api.read_interface_data().unwrap());
        a.allowed_ips = vec![IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(100, 64, 250, 10)), 32)];
        api.configure_peer(&a).unwrap();
        let host = api.read_interface_data().unwrap();
        show("updating a again", &host);
        assert_eq!(host.peers[&a.public_key].allowed_ips, a.allowed_ips);
        assert_eq!(host.peers[&b.public_key].allowed_ips, b.allowed_ips);

        api.remove_peer(&b.public_key).unwrap();
        assert_eq!(api.read_interface_data().unwrap().peers.len(), 1);

        let routed: std::collections::BTreeSet<IpAddr> = [IpAddr::V4(Ipv4Addr::new(100, 64, 250, 9))].into();
        crate::routes::sync(&name, &Default::default(), &routed).unwrap();
        crate::routes::sync(&name, &routed, &Default::default()).unwrap();

        // Read through a second handle, as `status` does.
        assert_eq!(NtApi::new(name.clone()).unwrap().read_interface_data().unwrap().peers.len(), 1);

        api.remove_interface();
        assert!(winnet::luid_by_alias(&name).unwrap().is_none(), "the adapter outlived its handle");

        // A restart: the name is free again at once.
        let mut again = NtApi::new(name.clone()).unwrap();
        again.create_interface().unwrap();
        again.remove_interface();
        assert!(winnet::luid_by_alias(&name).unwrap().is_none());
    }

    #[test]
    fn an_adapter_keeps_its_guid_across_starts_and_names_differ() {
        let parts = |g: GUID| (g.data1, g.data2, g.data3, g.data4);
        assert_eq!(parts(adapter_guid("wireserve0")), parts(adapter_guid("wireserve0")));
        assert_ne!(parts(adapter_guid("wireserve0")), parts(adapter_guid("wireserve1")));
    }
}
