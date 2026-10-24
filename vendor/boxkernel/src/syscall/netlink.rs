//! AF_NETLINK / NETLINK_ROUTE emulation (enter.c) — for hosts (Android
//! SELinux, hardened containers) that refuse real netlink sockets.
//!
//! PRoot substitutes an AF_UNIX/SOCK_DGRAM socket and answers rtnetlink
//! requests itself: NLMSG_ERROR(0) acks for reconfigures, interface/address
//! dumps built from getifaddrs(3), route dumps relayed through an unbound
//! host socket, and NLMSG_DONE terminators.

use std::cell::RefMut;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::Word;
use crate::tracee::mem::{peek_word, read_data, write_data};
use crate::tracee::reg::{Reg, RegVersion, peek_reg};
use crate::tracee::{FakeNetlinkSocket, MAX_FAKE_NETLINK_REPLY, Tracee};

// rtnetlink/netlink constants (ABI-stable).
const NLMSG_HDR_LEN: usize = 16;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_GETLINK: u16 = 18;
const RTM_GETADDR: u16 = 22;
const RTM_GETROUTE: u16 = 26;
const RTM_BASE: u16 = 16;
const RTM_MAX: u16 = 46;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_ACK: u16 = 4;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;

const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_ETHER: u16 = 1;
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x10000;

const IFA_F_PERMANENT: u8 = 0x80;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 200;
const RT_SCOPE_HOST: u8 = 254;

const IFNAMSIZ: usize = 16;

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}
fn nlmsg_length(payload: usize) -> usize {
    NLMSG_HDR_LEN + payload
}
fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}
fn rta_length(payload: usize) -> usize {
    4 + payload
}
fn rta_space(payload: usize) -> usize {
    rta_align(rta_length(payload))
}

// ==================================================================
// fd bookkeeping
// ==================================================================

/// `fake_netlink_socket()` — index of the bookkeeping entry for @fd.
pub fn fake_netlink_idx(tracee: &Tracee, fd: i32) -> Option<usize> {
    if fd < 0 {
        return None;
    }
    tracee.fake_netlink_fds.iter().position(|s| s.fd == fd)
}

pub fn is_fake_netlink_fd(tracee: &Tracee, fd: i32) -> bool {
    fake_netlink_idx(tracee, fd).is_some()
}

/// `unmark_fake_netlink_fd()` — the fd died; its pending reply dies with it.
pub fn unmark_fake_netlink_fd(tracee: &mut Tracee, fd: i32) {
    if let Some(i) = fake_netlink_idx(tracee, fd) {
        tracee.fake_netlink_fds.remove(i);
    }
}

pub fn is_netlink_route_fd(tracee: &Tracee, fd: i32) -> bool {
    fd >= 0 && tracee.netlink_route_fds.contains(&fd)
}

pub fn unmark_netlink_route_fd(tracee: &mut Tracee, fd: i32) {
    if let Some(i) = tracee.netlink_route_fds.iter().position(|&f| f == fd) {
        tracee.netlink_route_fds.remove(i);
    }
    if tracee.netlink_ack_pending && tracee.netlink_ack_fd == fd {
        tracee.netlink_ack_pending = false;
    }
}

// ==================================================================
// Host capability probe
// ==================================================================

/// `host_blocks_af_netlink()` — probe socket()+bind()+a doomed sendto().
/// Cached process-wide.
pub fn host_blocks_af_netlink(tracee: &Tracee) -> bool {
    const PROBE_UNKNOWN: i32 = 0;
    const PROBE_ALLOWED: i32 = 1;
    const PROBE_BLOCKED: i32 = 2;
    static CACHED: AtomicI32 = AtomicI32::new(PROBE_UNKNOWN);

    if CACHED.load(Ordering::Relaxed) != PROBE_UNKNOWN {
        return CACHED.load(Ordering::Relaxed) == PROBE_BLOCKED;
    }

    let fd = crate::sys::socket(
        libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        0, // NETLINK_ROUTE
    );
    if fd < 0 {
        let e = crate::sys::errno();
        CACHED.store(PROBE_BLOCKED, Ordering::Relaxed);
        crate::verbose!(
            Some(tracee),
            1,
            "AF_NETLINK socket denied by host ({}); enabling AF_UNIX fallback for sandbox helpers",
            crate::sys::strerror(e)
        );
        return true;
    }

    // sockaddr_nl { family = AF_NETLINK, rest 0 }.
    let mut snl = [0u8; 12];
    snl[0] = (libc::AF_NETLINK & 0xff) as u8;
    snl[1] = ((libc::AF_NETLINK >> 8) & 0xff) as u8;
    let rc = crate::sys::bind(fd, &snl);
    if rc < 0 {
        let e = crate::sys::errno();
        crate::sys::close(fd);
        CACHED.store(PROBE_BLOCKED, Ordering::Relaxed);
        crate::verbose!(
            Some(tracee),
            1,
            "AF_NETLINK bind denied by host ({}); enabling AF_UNIX fallback for sandbox helpers",
            crate::sys::strerror(e)
        );
        return true;
    }

    // Probe a write: nlmsghdr{len,type=RTM_NEWADDR,flags=REQUEST|ACK,seq=1}
    // + ifaddrmsg{family=AF_UNSPEC}.  Harmless; only outright send failure
    // means the message was denied.
    let mut req = [0u8; NLMSG_HDR_LEN + 8];
    let len = nlmsg_length(8) as u16;
    req[0..2].copy_from_slice(&len.to_ne_bytes());
    req[2..4].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
    req[4..6].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    // ifa_family = AF_UNSPEC already zeroed.

    let rc = crate::sys::sendto(fd, &req, libc::MSG_DONTWAIT, Some(&snl));
    let err = crate::sys::errno();
    crate::sys::close(fd);

    if rc < 0 && (err == libc::EACCES || err == libc::EPERM) {
        CACHED.store(PROBE_BLOCKED, Ordering::Relaxed);
        crate::verbose!(
            Some(tracee),
            1,
            "AF_NETLINK sendto denied by host ({}); enabling AF_UNIX fallback for sandbox helpers",
            crate::sys::strerror(err)
        );
        return true;
    }

    CACHED.store(PROBE_ALLOWED, Ordering::Relaxed);
    false
}

// ==================================================================
// msghdr/iovec walking
// ==================================================================

/// `msghdr_first_iovec()` — (base, len) of `iov[0]` in the msghdr at
/// @msghdr_addr.  msghdr layout: word msg_name; u32 msg_namelen (+pad);
/// word msg_iov; word msg_iovlen.
pub fn msghdr_first_iovec(tracee: &Tracee, msghdr_addr: Word) -> Option<(Word, Word)> {
    if msghdr_addr == 0 {
        return None;
    }
    let w = crate::tracee::reg::sizeof_word(tracee) as Word;
    crate::sys::clear_errno();
    let iov_ptr = peek_word(tracee, msghdr_addr + 2 * w);
    let iov_count = if crate::sys::errno() == 0 {
        peek_word(tracee, msghdr_addr + 3 * w)
    } else {
        0
    };
    crate::sys::clear_errno();
    if iov_ptr == 0 || iov_count == 0 {
        return None;
    }
    let base = peek_word(tracee, iov_ptr);
    let len = if crate::sys::errno() == 0 {
        peek_word(tracee, iov_ptr + w)
    } else {
        0
    };
    crate::sys::clear_errno();
    Some((base, len))
}

// ==================================================================
// Message builders
// ==================================================================

/// `nl_add_attr()`.
fn nl_add_attr(buf: &mut [u8], off: usize, max: usize, ty: u16, data: &[u8]) -> usize {
    let space = rta_space(data.len());
    if off + space > max {
        return off;
    }
    let rlen = rta_length(data.len()) as u16;
    buf[off..off + 2].copy_from_slice(&rlen.to_ne_bytes());
    buf[off + 2..off + 4].copy_from_slice(&ty.to_ne_bytes());
    let data_off = off + rta_length(0);
    buf[data_off..data_off + data.len()].copy_from_slice(data);
    buf[data_off + data.len()..off + space].fill(0);
    off + space
}

fn write_hdr(buf: &mut [u8], start: usize, len: usize, ty: u16, flags: u16, seq: u32, pid: u32) {
    buf[start..start + 4].copy_from_slice(&(len as u32).to_ne_bytes());
    buf[start + 4..start + 6].copy_from_slice(&ty.to_ne_bytes());
    buf[start + 6..start + 8].copy_from_slice(&flags.to_ne_bytes());
    buf[start + 8..start + 12].copy_from_slice(&seq.to_ne_bytes());
    buf[start + 12..start + 16].copy_from_slice(&pid.to_ne_bytes());
}

/// `nl_build_link()`.  ifinfomsg: u8 family, u8 pad, u16 type,
/// i32 index, u32 flags, u32 change (16 bytes).
#[allow(clippy::too_many_arguments)]
fn nl_build_link(
    buf: &mut [u8],
    start: usize,
    max: usize,
    seq: u32,
    pid: u32,
    nlflags: u16,
    ifindex: i32,
    iftype: u16,
    ifflags: u32,
    mtu: u32,
    name: &[u8],
    hwaddr: &[u8],
) -> usize {
    if start + NLMSG_HDR_LEN + nlmsg_align(16) > max {
        return start;
    }

    let mut ifi = [0u8; 16];
    ifi[2..4].copy_from_slice(&iftype.to_ne_bytes());
    ifi[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    let flags = ifflags
        | if (ifflags & IFF_RUNNING) != 0 {
            IFF_LOWER_UP
        } else {
            0
        };
    ifi[8..12].copy_from_slice(&flags.to_ne_bytes());
    // ifi_change = 0

    let mut off = start + NLMSG_HDR_LEN;
    buf[off..off + 16].copy_from_slice(&ifi);
    off += nlmsg_align(16);

    let mut namez = name.to_vec();
    namez.push(0);
    off = nl_add_attr(buf, off, max, IFLA_IFNAME, &namez);
    off = nl_add_attr(buf, off, max, IFLA_MTU, &mtu.to_ne_bytes());
    off = nl_add_attr(buf, off, max, IFLA_TXQLEN, &1000u32.to_ne_bytes());
    let operstate: u8 = if (ifflags & IFF_UP) != 0 { 6 } else { 2 };
    off = nl_add_attr(buf, off, max, IFLA_OPERSTATE, &[operstate]);
    if !hwaddr.is_empty() {
        let fill = if iftype == ARPHRD_LOOPBACK {
            0x00
        } else {
            0xff
        };
        let mut brd = vec![fill; hwaddr.len().max(8)];
        brd.truncate(hwaddr.len());
        off = nl_add_attr(buf, off, max, IFLA_ADDRESS, hwaddr);
        off = nl_add_attr(buf, off, max, IFLA_BROADCAST, &brd);
    }

    let len = off - start;
    write_hdr(buf, start, len, RTM_NEWLINK, nlflags, seq, pid);
    start + nlmsg_align(len)
}

/// `nl_build_addr()`.  ifaddrmsg: u8 family, u8 prefixlen, u8 flags,
/// u8 scope, u32 index (8 bytes).
#[allow(clippy::too_many_arguments)]
fn nl_build_addr(
    buf: &mut [u8],
    start: usize,
    max: usize,
    seq: u32,
    pid: u32,
    nlflags: u16,
    family: i32,
    ifindex: i32,
    addr: &[u8],
    prefixlen: u8,
    scope: u8,
    label: Option<&[u8]>,
) -> usize {
    if start + NLMSG_HDR_LEN + nlmsg_align(8) > max {
        return start;
    }

    let mut ifa = [0u8; 8];
    ifa[0] = family as u8;
    ifa[1] = prefixlen;
    ifa[2] = IFA_F_PERMANENT;
    ifa[3] = scope;
    ifa[4..8].copy_from_slice(&ifindex.to_ne_bytes());

    let mut off = start + NLMSG_HDR_LEN;
    buf[off..off + 8].copy_from_slice(&ifa);
    off += nlmsg_align(8);

    off = nl_add_attr(buf, off, max, IFA_ADDRESS, addr);
    off = nl_add_attr(buf, off, max, IFA_LOCAL, addr);
    if family == libc::AF_INET {
        if let Some(l) = label {
            let mut lz = l.to_vec();
            lz.push(0);
            off = nl_add_attr(buf, off, max, IFA_LABEL, &lz);
        }
    }

    let len = off - start;
    write_hdr(buf, start, len, RTM_NEWADDR, nlflags, seq, pid);
    start + nlmsg_align(len)
}

/// `nl_build_done()` — NLMSG_DONE + i32 error.
fn nl_build_done(buf: &mut [u8], off: usize, max: usize, seq: u32, pid: u32) -> usize {
    let len = NLMSG_HDR_LEN + 4;
    if off + nlmsg_align(len) > max {
        return off;
    }
    write_hdr(buf, off, len, NLMSG_DONE, NLM_F_MULTI, seq, pid);
    buf[off + NLMSG_HDR_LEN..off + len].copy_from_slice(&0i32.to_ne_bytes());
    off + nlmsg_align(len)
}

/// `nl_build_error()` — NLMSG_ERROR{error,msg}.
fn nl_build_error(buf: &mut [u8], off: usize, max: usize, seq: u32, pid: u32, error: i32) -> usize {
    let len = NLMSG_HDR_LEN + 4 + NLMSG_HDR_LEN;
    if off + nlmsg_align(len) > max {
        return off;
    }
    write_hdr(buf, off, len, NLMSG_ERROR, 0, seq, pid);
    buf[off + NLMSG_HDR_LEN..off + NLMSG_HDR_LEN + 4].copy_from_slice(&error.to_ne_bytes());
    // err.msg: zeroed original header.
    buf[off + NLMSG_HDR_LEN + 4..off + 2 * NLMSG_HDR_LEN + 4].fill(0);
    off + nlmsg_align(len)
}

/// `nl_request_is_loopback()`.
fn nl_request_is_loopback(req: &[u8]) -> bool {
    let mut off = NLMSG_HDR_LEN;
    if req.len() < off + 16 {
        return true; // no selector -> loopback
    }
    let ifindex = i32::from_ne_bytes(req[off + 4..off + 8].try_into().unwrap());
    off += nlmsg_align(16);

    let mut name = [0u8; IFNAMSIZ];
    let mut have_name = false;
    while off + 4 <= req.len() {
        let rlen = u16::from_ne_bytes(req[off..off + 2].try_into().unwrap()) as usize;
        let rtype = u16::from_ne_bytes(req[off + 2..off + 4].try_into().unwrap());
        if rlen < 4 || off + rlen > req.len() {
            break;
        }
        if rtype == IFLA_IFNAME {
            let dlen = rlen - rta_length(0);
            let cpy = dlen.min(IFNAMSIZ - 1);
            name[..cpy].copy_from_slice(&req[off + rta_length(0)..off + rta_length(0) + cpy]);
            have_name = true;
        }
        off += rta_align(rlen);
    }

    if have_name {
        return &name[..2] == b"lo" && name[2] == 0;
    }
    ifindex == 0 || ifindex == 1
}

/// `nl_request_link_target()` — (ifi_index, IFLA_IFNAME).
fn nl_request_link_target(req: &[u8]) -> (i32, [u8; IFNAMSIZ]) {
    let mut name = [0u8; IFNAMSIZ];
    let mut off = NLMSG_HDR_LEN;
    if req.len() < off + 16 {
        return (0, name);
    }
    let ifindex = i32::from_ne_bytes(req[off + 4..off + 8].try_into().unwrap());
    off += nlmsg_align(16);
    while off + 4 <= req.len() {
        let rlen = u16::from_ne_bytes(req[off..off + 2].try_into().unwrap()) as usize;
        let rtype = u16::from_ne_bytes(req[off + 2..off + 4].try_into().unwrap());
        if rlen < 4 || off + rlen > req.len() {
            break;
        }
        if rtype == IFLA_IFNAME {
            let dlen = rlen - rta_length(0);
            let cpy = dlen.min(IFNAMSIZ - 1);
            name[..cpy].copy_from_slice(&req[off + rta_length(0)..off + rta_length(0) + cpy]);
        }
        off += rta_align(rlen);
    }
    (ifindex, name)
}

/// `write_fake_netlink_sockname()` — synthetic sockaddr_nl into the
/// (addr_ptr, size_ptr) pair.  sockaddr_nl: u16 family, u16 pad, u32 pid,
/// u32 groups (12 bytes).
pub fn write_fake_netlink_sockname(
    tracee: &Tracee,
    addr_ptr: Word,
    size_ptr: Word,
    nl_pid: u32,
) -> i32 {
    if size_ptr == 0 {
        return -libc::EINVAL;
    }
    crate::sys::clear_errno();
    let in_size = crate::tracee::mem::peek_uint32(tracee, size_ptr);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }

    let mut snl = [0u8; 12];
    snl[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());
    snl[4..8].copy_from_slice(&nl_pid.to_ne_bytes());

    if addr_ptr != 0 && in_size > 0 {
        let copy = (in_size as usize).min(snl.len());
        if write_data(tracee, addr_ptr, &snl[..copy]) < 0 {
            return -libc::EFAULT;
        }
    }

    crate::tracee::mem::poke_uint32(tracee, size_ptr, snl.len() as u32);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }
    0
}

fn nl_prefixlen(mask: &[u8]) -> u8 {
    let mut bits = 0u8;
    for &b in mask {
        if b == 0xff {
            bits += 8;
            continue;
        }
        let mut b = b;
        while b & 0x80 != 0 {
            bits += 1;
            b <<= 1;
        }
        break;
    }
    bits
}

fn nl_addr_scope(family: i32, addr: &[u8]) -> u8 {
    if family == libc::AF_INET {
        if addr[0] == 127 {
            RT_SCOPE_HOST
        } else if addr[0] == 169 && addr[1] == 254 {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        }
    } else {
        let loopv6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
        if addr == loopv6 {
            RT_SCOPE_HOST
        } else if addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80 {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        }
    }
}

fn nl_build_loopback_link(
    buf: &mut [u8],
    off: usize,
    max: usize,
    seq: u32,
    pid: u32,
    nlflags: u16,
) -> usize {
    nl_build_link(
        buf,
        off,
        max,
        seq,
        pid,
        nlflags,
        1,
        ARPHRD_LOOPBACK,
        IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
        65536,
        b"lo",
        &[0; 6],
    )
}

fn nl_build_loopback_addr(
    buf: &mut [u8],
    off: usize,
    max: usize,
    seq: u32,
    pid: u32,
    family: i32,
    nlflags: u16,
) -> usize {
    let v4 = [127, 0, 0, 1u8];
    let v6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
    if family == libc::AF_INET6 {
        nl_build_addr(
            buf,
            off,
            max,
            seq,
            pid,
            nlflags,
            libc::AF_INET6,
            1,
            &v6,
            128,
            RT_SCOPE_HOST,
            None,
        )
    } else {
        nl_build_addr(
            buf,
            off,
            max,
            seq,
            pid,
            nlflags,
            libc::AF_INET,
            1,
            &v4,
            8,
            RT_SCOPE_HOST,
            Some(b"lo"),
        )
    }
}

// ==================================================================
// Host interface enumeration (getifaddrs + ioctl MTU/hwaddr)
// ==================================================================

struct HostIf {
    name: Vec<u8>,
    ifflags: u32,
    iftype: u16,
    ifindex: i32,
    mtu: u32,
    hwaddr: Vec<u8>,
    addrs: Vec<(i32, Vec<u8>, Vec<u8>)>, // (family, addr, netmask)
}

fn host_interfaces() -> Vec<HostIf> {
    let list = match crate::sys::IfAddrs::get() {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };
    let sock = crate::sys::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);

    let mut out: Vec<HostIf> = Vec::new();
    for ifa in list.iter() {
        let name = ifa.name().to_bytes().to_vec();

        let idx = out.iter().position(|h: &HostIf| h.name == name);
        let ifflags = ifa.flags();
        let entry = match idx {
            Some(i) => &mut out[i],
            None => {
                out.push(HostIf {
                    name: name.clone(),
                    ifflags,
                    iftype: if (ifflags & IFF_LOOPBACK) != 0 {
                        ARPHRD_LOOPBACK
                    } else {
                        ARPHRD_ETHER
                    },
                    ifindex: crate::sys::if_nametoindex(ifa.name()) as i32,
                    mtu: if (ifflags & IFF_LOOPBACK) != 0 {
                        65536
                    } else {
                        1500
                    },
                    hwaddr: Vec::new(),
                    addrs: Vec::new(),
                });
                out.last_mut().unwrap()
            }
        };

        // sockaddr_ll: u16 family, u16 proto, i32 ifindex, u16 hatype,
        // u8 pkttype, u8 halen, u8 addr[8]
        if let Some(sll) = ifa.addr_ll() {
            if sll.sll_ifindex != 0 {
                entry.ifindex = sll.sll_ifindex;
            }
            entry.iftype = sll.sll_hatype;
            let halen = sll.sll_halen as usize;
            if halen > 0 && halen <= 8 {
                entry.hwaddr = sll.sll_addr[..halen].to_vec();
            }
        } else if let Some(sin) = ifa.addr_in() {
            let addr = sin.sin_addr.s_addr.to_ne_bytes().to_vec();
            let mask = ifa
                .netmask_in()
                .map(|m| m.sin_addr.s_addr.to_ne_bytes().to_vec())
                .unwrap_or_default();
            entry.addrs.push((libc::AF_INET, addr, mask));
        } else if let Some(sin6) = ifa.addr_in6() {
            let addr = sin6.sin6_addr.s6_addr.to_vec();
            let mask = ifa
                .netmask_in6()
                .map(|m| m.sin6_addr.s6_addr.to_vec())
                .unwrap_or_default();
            entry.addrs.push((libc::AF_INET6, addr, mask));
        }
    }

    // Best-effort MTU/hwaddr via ioctl when no AF_PACKET entry filled them.
    // ifreq layout: ifr_name[16] then the ifr_ifru union — read union fields
    // by byte offset (ifr_ifru starts at offset 16; sockaddr members at
    // +0 family, +2 data).
    fn ifru(ifr: &libc::ifreq) -> &[u8] {
        &crate::sys::as_bytes(ifr)[16..]
    }
    if sock >= 0 {
        for entry in out.iter_mut() {
            let mut ifr: libc::ifreq = crate::sys::zeroed();
            let n = entry.name.len().min(IFNAMSIZ - 1);
            for (dst, &src) in ifr.ifr_name.iter_mut().zip(entry.name.iter().take(n)) {
                *dst = src as libc::c_char;
            }
            if crate::sys::ioctl_val(sock, libc::SIOCGIFMTU, &mut ifr) == 0 {
                entry.mtu = i32::from_ne_bytes(ifru(&ifr)[0..4].try_into().unwrap()) as u32;
            }
            if entry.hwaddr.is_empty()
                && crate::sys::ioctl_val(sock, libc::SIOCGIFHWADDR, &mut ifr) == 0
            {
                entry.iftype = u16::from_ne_bytes(ifru(&ifr)[0..2].try_into().unwrap());
                entry.hwaddr = ifru(&ifr)[2..8].to_vec();
            }
        }
        crate::sys::close(sock);
    }
    out
}

/// `build_host_links()` — RTM_NEWLINK per host interface (or the one
/// matching `want_name`/`want_index` for a single get).
fn build_host_links(
    out: &mut [u8],
    max: usize,
    seq: u32,
    pid: u32,
    want_name: Option<&[u8]>,
    want_index: i32,
    dump: bool,
    built: &mut i32,
) -> usize {
    *built = 0;
    let mut off = 0usize;
    let ifs = host_interfaces();
    for h in &ifs {
        if !dump {
            match want_name {
                Some(w) if !w.is_empty() => {
                    let wz: Vec<u8> = w.iter().cloned().take_while(|&b| b != 0).collect();
                    if h.name != wz {
                        continue;
                    }
                }
                _ => {
                    if want_index > 0 && h.ifindex != want_index {
                        continue;
                    }
                }
            }
        }
        if off + 256 > max {
            break;
        }
        off = nl_build_link(
            out,
            off,
            max,
            seq,
            pid,
            if dump { NLM_F_MULTI } else { 0 },
            h.ifindex,
            h.iftype,
            h.ifflags,
            h.mtu,
            &h.name,
            &h.hwaddr,
        );
        *built += 1;
        if !dump {
            break;
        }
    }
    off
}

/// `build_host_addrs()` — RTM_NEWADDR per host address.
fn build_host_addrs(
    out: &mut [u8],
    max: usize,
    seq: u32,
    pid: u32,
    want_family: i32,
    dump: bool,
    built: &mut i32,
) -> usize {
    *built = 0;
    let mut off = 0usize;
    for h in &host_interfaces() {
        for (family, addr, mask) in &h.addrs {
            if want_family != libc::AF_UNSPEC && *family != want_family {
                continue;
            }
            let prefixlen = if !mask.is_empty() {
                nl_prefixlen(mask)
            } else if *family == libc::AF_INET {
                32
            } else {
                128
            };
            let scope = nl_addr_scope(*family, addr);
            if off + 256 > max {
                break;
            }
            off = nl_build_addr(
                out,
                off,
                max,
                seq,
                pid,
                if dump { NLM_F_MULTI } else { 0 },
                *family,
                h.ifindex,
                addr,
                prefixlen,
                scope,
                Some(&h.name),
            );
            *built += 1;
        }
    }
    off
}

/// `relay_route_dump()` — run an unbound RTM_GETROUTE dump on the host and
/// copy the replies back with the tracee's seq/pid.
fn relay_route_dump(req: &[u8], out: &mut [u8], max: usize, seq: u32, pid: u32) -> usize {
    let family = if req.len() > NLMSG_HDR_LEN {
        req[NLMSG_HDR_LEN]
    } else {
        0
    };

    let fd = crate::sys::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        return 0;
    }
    let tv = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    crate::sys::setsockopt_val(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv);

    // nlmsghdr + rtmsg{rtm_family,...}
    let mut dreq = [0u8; NLMSG_HDR_LEN + 32];
    let dlen = nlmsg_length(32) as u16;
    dreq[0..4].copy_from_slice(&(dlen as u32).to_ne_bytes());
    dreq[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
    dreq[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    dreq[8..12].copy_from_slice(&seq.to_ne_bytes());
    dreq[NLMSG_HDR_LEN] = family;

    let mut snl = [0u8; 12];
    snl[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());
    let rc = crate::sys::sendto(fd, &dreq[..nlmsg_length(32)], 0, Some(&snl));
    if rc < 0 {
        crate::sys::close(fd);
        return 0;
    }

    let mut off = 0usize;
    let mut done = false;
    let mut saw_done = false;
    let mut rounds = 0;
    while !done && rounds < 64 {
        rounds += 1;
        let mut buf = [0u8; 8192];
        let n = crate::sys::recv(fd, &mut buf, 0);
        if n <= 0 {
            break;
        }
        let mut len = n as usize;
        let mut pos = 0usize;
        while pos + NLMSG_HDR_LEN <= len {
            let mlen = u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            if mlen < NLMSG_HDR_LEN || mlen > len - pos {
                break;
            }
            let aligned = nlmsg_align(mlen);
            if off + aligned + 64 > max {
                done = true;
                break;
            }
            out[off..off + mlen].copy_from_slice(&buf[pos..pos + mlen]);
            out[off + 8..off + 12].copy_from_slice(&seq.to_ne_bytes());
            out[off + 12..off + 16].copy_from_slice(&pid.to_ne_bytes());
            for i in mlen..aligned {
                out[off + i] = 0;
            }
            let ty = u16::from_ne_bytes(buf[pos + 4..pos + 6].try_into().unwrap());
            off += aligned;
            if ty == NLMSG_DONE {
                saw_done = true;
                done = true;
                break;
            }
            pos += aligned;
            let _ = &mut len;
        }
    }
    crate::sys::close(fd);

    if off == 0 {
        return 0;
    }
    if !saw_done {
        off = nl_build_done(out, off, max, seq, pid);
    }
    off
}

// ==================================================================
// Reply construction / delivery
// ==================================================================

/// `build_fake_netlink_reply()` — fill `sock.reply` with the response the
/// kernel would give to the request at `buf_addr`/`buf_len`.
pub fn build_fake_netlink_reply(
    tracee: &mut Tracee,
    sock_idx: usize,
    buf_addr: Word,
    buf_len: Word,
) {
    let mut out = vec![0u8; MAX_FAKE_NETLINK_REPLY];
    let max = out.len();
    let pid = tracee.pid as u32;

    let mut seq = 0u32;
    let mut off = 0usize;

    let mut req = [0u8; 256];
    if buf_addr != 0 && buf_len >= NLMSG_HDR_LEN as Word {
        let req_len = (buf_len as usize).min(req.len());
        if read_data(tracee, &mut req[..req_len], buf_addr) >= 0 {
            let ty = u16::from_ne_bytes(req[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(req[6..8].try_into().unwrap());
            seq = u32::from_ne_bytes(req[8..12].try_into().unwrap());
            let dump = (flags & NLM_F_DUMP) == NLM_F_DUMP;
            let req = &req[..req_len];

            match ty {
                RTM_GETLINK => {
                    let (want_index, want_name) = nl_request_link_target(req);
                    let mut n = 0;
                    off = build_host_links(
                        &mut out,
                        max,
                        seq,
                        pid,
                        if dump { None } else { Some(&want_name) },
                        if dump { 0 } else { want_index },
                        dump,
                        &mut n,
                    );
                    if n == 0 {
                        off = 0;
                        if dump {
                            off = nl_build_loopback_link(&mut out, off, max, seq, pid, NLM_F_MULTI);
                        } else if nl_request_is_loopback(req) {
                            off = nl_build_loopback_link(&mut out, off, max, seq, pid, 0);
                        } else {
                            off = nl_build_error(&mut out, off, max, seq, pid, -libc::ENODEV);
                        }
                    }
                    if dump {
                        off = nl_build_done(&mut out, off, max, seq, pid);
                    }
                }
                RTM_GETADDR => {
                    let family = if req.len() > NLMSG_HDR_LEN {
                        req[NLMSG_HDR_LEN] as i32
                    } else {
                        0
                    };
                    let want_family = if family == libc::AF_INET || family == libc::AF_INET6 {
                        family
                    } else {
                        libc::AF_UNSPEC
                    };
                    let mut n = 0;
                    off = build_host_addrs(&mut out, max, seq, pid, want_family, dump, &mut n);
                    if n == 0 {
                        off = 0;
                        if family == 0 || family == libc::AF_INET {
                            off = nl_build_loopback_addr(
                                &mut out,
                                off,
                                max,
                                seq,
                                pid,
                                libc::AF_INET,
                                if dump { NLM_F_MULTI } else { 0 },
                            );
                        }
                        if family == 0 || family == libc::AF_INET6 {
                            off = nl_build_loopback_addr(
                                &mut out,
                                off,
                                max,
                                seq,
                                pid,
                                libc::AF_INET6,
                                if dump { NLM_F_MULTI } else { 0 },
                            );
                        }
                    }
                    if dump {
                        off = nl_build_done(&mut out, off, max, seq, pid);
                    }
                }
                RTM_GETROUTE => {
                    if dump {
                        off = relay_route_dump(req, &mut out, max, seq, pid);
                        if off == 0 {
                            off = nl_build_done(&mut out, off, max, seq, pid);
                        }
                    } else {
                        off = nl_build_error(&mut out, off, max, seq, pid, 0);
                    }
                }
                _ => {
                    if dump {
                        off = nl_build_done(&mut out, off, max, seq, pid);
                    } else {
                        off = nl_build_error(&mut out, off, max, seq, pid, 0);
                    }
                }
            }
        }
    }

    // Never leave a request unanswered.
    if off == 0 {
        off = nl_build_error(&mut out, off, max, seq, pid, -libc::EINVAL);
    }

    out.truncate(off);
    let sock: &mut FakeNetlinkSocket = &mut tracee.fake_netlink_fds[sock_idx];
    sock.reply = out;
    sock.reply_off = 0;
}

/// `fake_netlink_datagram_len()` — split a reply into per-datagram chunks;
/// the NLMSG_DONE terminator always gets a datagram of its own.
fn fake_netlink_datagram_len(reply: &[u8]) -> usize {
    let len = reply.len();
    let mut off = 0usize;
    while off + NLMSG_HDR_LEN <= len {
        let mlen = u32::from_ne_bytes(reply[off..off + 4].try_into().unwrap()) as usize;
        if mlen < NLMSG_HDR_LEN || off + mlen > len {
            break;
        }
        let ty = u16::from_ne_bytes(reply[off + 4..off + 6].try_into().unwrap());
        if ty == NLMSG_DONE {
            break;
        }
        off += nlmsg_align(mlen);
    }
    if off == 0 || off > len { len } else { off }
}

/// `pending_fake_netlink_datagram()` — slice + length of the next datagram.
pub fn pending_fake_netlink_datagram(sock: &FakeNetlinkSocket) -> Option<(&[u8], usize)> {
    if sock.reply.is_empty() {
        return None;
    }
    let reply = &sock.reply[sock.reply_off..];
    let len = fake_netlink_datagram_len(reply);
    Some((reply, len))
}

/// `consume_fake_netlink_datagram()`.
pub fn consume_fake_netlink_datagram(sock: &mut FakeNetlinkSocket, datagram: usize) {
    sock.reply_off += datagram;
    if sock.reply_off >= sock.reply.len() {
        sock.reply.clear();
        sock.reply_off = 0;
    }
}

/// `scatter_fake_netlink_reply()` — copy `reply` into the tracee's iovec
/// array; returns bytes written.
pub fn scatter_fake_netlink_reply(
    tracee: &Tracee,
    iov_ptr: Word,
    iov_count: Word,
    reply: &[u8],
) -> usize {
    let w = crate::tracee::reg::sizeof_word(tracee) as Word;
    let mut done = 0usize;
    let mut i: Word = 0;
    while i < iov_count && done < reply.len() {
        let base = peek_word(tracee, iov_ptr + i * 2 * w);
        let len = if crate::sys::errno() == 0 {
            peek_word(tracee, iov_ptr + i * 2 * w + w)
        } else {
            0
        };
        crate::sys::clear_errno();
        let mut chunk = reply.len() - done;
        if chunk > len as usize {
            chunk = len as usize;
        }
        if base != 0 && chunk > 0 && write_data(tracee, base, &reply[done..done + chunk]) < 0 {
            break;
        }
        done += chunk;
        i += 1;
    }
    done
}

// ==================================================================
// Real-socket ack rewriting (fake_netns)
// ==================================================================

/// `nl_type_reconfigures()` — rtnetlink groups: NEW/DEL/GET/SET;
/// everything but GET reconfigures.
fn nl_type_reconfigures(ty: u16) -> bool {
    if !(RTM_BASE..=RTM_MAX).contains(&ty) {
        return false;
    }
    ((ty - RTM_BASE) & 3) != 2
}

/// `is_netns_netlink_fd()`.
pub fn is_netns_netlink_fd(tracee: &Tracee, fd: i32) -> bool {
    tracee.fake_netns && is_netlink_route_fd(tracee, fd)
}

/// `note_netns_netlink_request()`.
pub fn note_netns_netlink_request(tracee: &mut Tracee, fd: i32, buf_addr: Word, buf_len: Word) {
    if !is_netns_netlink_fd(tracee, fd) {
        return;
    }
    if buf_addr == 0 || buf_len < NLMSG_HDR_LEN as Word {
        return;
    }
    let mut hdr = [0u8; NLMSG_HDR_LEN];
    if read_data(tracee, &mut hdr, buf_addr) < 0 {
        return;
    }
    let ty = u16::from_ne_bytes(hdr[4..6].try_into().unwrap());
    if !nl_type_reconfigures(ty) {
        return;
    }
    tracee.netlink_ack_pending = true;
    tracee.netlink_ack_fd = fd;
    tracee.netlink_ack_seq = u32::from_ne_bytes(hdr[8..12].try_into().unwrap());
}

/// `note_netns_netlink_reply()`.
pub fn note_netns_netlink_reply(tracee: &mut Tracee, fd: i32) {
    if !tracee.netlink_ack_pending || tracee.netlink_ack_fd != fd {
        return;
    }
    tracee.sysexit_pending = true;
    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
}

/// `handle_netlink_reply_exit()` — at the exit of recvfrom/recvmsg, turn
/// the kernel's EPERM/EACCES NLMSG_ERROR into an ack for the noted request.
pub fn handle_netlink_reply_exit(tracee: &mut Tracee, is_recvfrom: bool) {
    if !tracee.netlink_ack_pending {
        return;
    }
    if peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as i32 != tracee.netlink_ack_fd {
        return;
    }
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64;
    if result <= 0 {
        return;
    }

    let (buf_addr, buf_len, flags);
    if is_recvfrom {
        buf_addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
        buf_len = peek_reg(tracee, RegVersion::Original, Reg::Sysarg3);
        flags = peek_reg(tracee, RegVersion::Original, Reg::Sysarg4) as i32;
    } else {
        match msghdr_first_iovec(tracee, peek_reg(tracee, RegVersion::Original, Reg::Sysarg2)) {
            Some((b, l)) => {
                buf_addr = b;
                buf_len = l;
            }
            None => return,
        }
        flags = peek_reg(tracee, RegVersion::Original, Reg::Sysarg3) as i32;
    }

    let mut len = result as usize;
    if len > buf_len as usize {
        len = buf_len as usize;
    }
    len = len.min(512);
    if buf_addr == 0 || len < NLMSG_HDR_LEN + 4 {
        return;
    }
    let mut reply = [0u8; 512];
    if read_data(tracee, &mut reply[..len], buf_addr) < 0 {
        return;
    }

    let mut off = 0usize;
    while off + NLMSG_HDR_LEN + 4 <= len {
        let hlen = u32::from_ne_bytes(reply[off..off + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(reply[off + 4..off + 6].try_into().unwrap());
        let hseq = u32::from_ne_bytes(reply[off + 8..off + 12].try_into().unwrap());
        if hlen < NLMSG_HDR_LEN {
            break;
        }
        if ty == NLMSG_ERROR && hseq == tracee.netlink_ack_seq {
            let error = i32::from_ne_bytes(
                reply[off + NLMSG_HDR_LEN..off + NLMSG_HDR_LEN + 4]
                    .try_into()
                    .unwrap(),
            );
            if error != -libc::EPERM && error != -libc::EACCES {
                break;
            }
            crate::tracee::mem::poke_uint32(
                tracee,
                buf_addr + off as Word + NLMSG_HDR_LEN as Word,
                0,
            );
            if crate::sys::errno() == 0 {
                crate::verbose!(
                    Some(tracee),
                    1,
                    "netlink: acked the request denied to the tracee's would-be network namespace ({})",
                    crate::sys::strerror(-error)
                );
            }
            crate::sys::clear_errno();
            break;
        }
        off += nlmsg_align(hlen);
    }

    if (flags & libc::MSG_PEEK) == 0 {
        tracee.netlink_ack_pending = false;
    }
}

// ==================================================================
// ioctl(SIOCGIFINDEX)
// ==================================================================

/// `maybe_fake_siocgifindex()` — resolve ifr_name → ifr_ifindex in the
/// tracer (Android denies the ioctl itself).  Returns true when answered.
pub fn maybe_fake_siocgifindex(tracee: &Tracee, cmd: Word, arg: Word) -> bool {
    if cmd != libc::SIOCGIFINDEX as Word || arg == 0 {
        return false;
    }
    let mut name = [0u8; IFNAMSIZ];
    if read_data(tracee, &mut name, arg) < 0 {
        return false;
    }
    name[IFNAMSIZ - 1] = 0;
    // SAFETY: name[..IFNAMSIZ] is NUL-terminated by construction.
    let name_c = unsafe { std::ffi::CStr::from_ptr(name.as_ptr() as *const libc::c_char) };

    let mut ifindex = crate::sys::if_nametoindex(name_c) as i32;
    if ifindex <= 0 {
        if name_c.to_bytes() != b"lo" {
            return false;
        }
        ifindex = 1;
    }
    write_data(tracee, arg + IFNAMSIZ as Word, &ifindex.to_ne_bytes()) >= 0
}

pub fn mark_fake_netlink_fd(tracee: &mut Tracee, fd: i32) {
    tracee.fake_netlink_fds.push(FakeNetlinkSocket {
        fd,
        reply: Vec::new(),
        reply_off: 0,
    });
}

pub fn mark_netlink_route_fd(tracee: &mut Tracee, fd: i32) {
    if fd >= 0 && !tracee.netlink_route_fds.contains(&fd) {
        tracee.netlink_route_fds.push(fd);
    }
}

/// Helper for callers that hold a `RefMut<Tracee>` slot — no-op wrapper to
/// keep signatures uniform.
pub fn sock_of<'a>(t: &'a mut RefMut<'a, Tracee>, _idx: usize) -> &'a mut FakeNetlinkSocket {
    &mut t.fake_netlink_fds[_idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, fork_child, test_tracee};

    fn hdr_fields(buf: &[u8], at: usize) -> (u32, u16, u16, u32, u32) {
        (
            u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()),
            u16::from_ne_bytes(buf[at + 4..at + 6].try_into().unwrap()),
            u16::from_ne_bytes(buf[at + 6..at + 8].try_into().unwrap()),
            u32::from_ne_bytes(buf[at + 8..at + 12].try_into().unwrap()),
            u32::from_ne_bytes(buf[at + 12..at + 16].try_into().unwrap()),
        )
    }

    #[test]
    fn alignment_helpers() {
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(rta_length(4), 8);
        assert_eq!(rta_space(4), 8);
        assert_eq!(rta_space(5), 12); // pad to 4
    }

    #[test]
    fn add_attr_layout() {
        let mut buf = [0u8; 64];
        let off = nl_add_attr(&mut buf, 0, 64, IFLA_IFNAME, b"lo\0");
        assert_eq!(off, 8); // rta_length(3)=7 -> align 8
        assert_eq!(u16::from_ne_bytes(buf[0..2].try_into().unwrap()), 7);
        assert_eq!(
            u16::from_ne_bytes(buf[2..4].try_into().unwrap()),
            IFLA_IFNAME
        );
        assert_eq!(&buf[4..7], b"lo\0");
        // Overflow: returns off unchanged.
        assert_eq!(nl_add_attr(&mut buf, 60, 64, IFLA_MTU, &[1, 2, 3, 4]), 60);
    }

    #[test]
    fn build_done_and_error() {
        let mut buf = [0u8; 128];
        let end = nl_build_done(&mut buf, 0, 128, 7, 42);
        let (len, ty, flags, seq, pid) = hdr_fields(&buf, 0);
        assert_eq!((len, ty, seq, pid), (20, NLMSG_DONE, 7, 42));
        assert_eq!(flags & NLM_F_MULTI, NLM_F_MULTI);
        assert_eq!(end, nlmsg_align(20));
        // Error carries the code at hdr+4.
        let end = nl_build_error(&mut buf, 40, 128, 9, 1, -libc::EPERM);
        let (len, ty, _f, seq, pid) = hdr_fields(&buf, 40);
        assert_eq!((len, ty, seq, pid), (36, NLMSG_ERROR, 9, 1));
        assert_eq!(
            i32::from_ne_bytes(buf[56..60].try_into().unwrap()),
            -libc::EPERM
        );
        assert_eq!(end, 40 + nlmsg_align(36));
        // No room -> unchanged offset.
        assert_eq!(nl_build_done(&mut buf, 120, 128, 1, 1), 120);
        assert_eq!(nl_build_error(&mut buf, 120, 128, 1, 1, 0), 120);
    }

    #[test]
    fn build_link_lo_structure() {
        let mut buf = [0u8; 512];
        let end = nl_build_loopback_link(&mut buf, 0, 512, 3, 9, NLM_F_MULTI);
        let (len, ty, flags, seq, pid) = hdr_fields(&buf, 0);
        assert_eq!((ty, seq, pid), (RTM_NEWLINK, 3, 9));
        assert_eq!(flags & NLM_F_MULTI, NLM_F_MULTI);
        assert_eq!(end, nlmsg_align(len as usize));
        // ifinfomsg at +16: type=ARPHRD_LOOPBACK, index=1, flags include UP|RUNNING|LOWER_UP.
        let ifi = &buf[16..32];
        assert_eq!(
            u16::from_ne_bytes(ifi[2..4].try_into().unwrap()),
            ARPHRD_LOOPBACK
        );
        assert_eq!(i32::from_ne_bytes(ifi[4..8].try_into().unwrap()), 1);
        let f = u32::from_ne_bytes(ifi[8..12].try_into().unwrap());
        assert!(f & IFF_UP != 0 && f & IFF_LOOPBACK != 0);
        assert!(f & IFF_LOWER_UP != 0); // RUNNING -> LOWER_UP added
        // First attr should be IFLA_IFNAME "lo".
        assert_eq!(
            u16::from_ne_bytes(buf[32..34].try_into().unwrap()),
            rta_length(3) as u16
        );
        assert_eq!(
            u16::from_ne_bytes(buf[34..36].try_into().unwrap()),
            IFLA_IFNAME
        );
        assert_eq!(&buf[36..39], b"lo\0");
    }

    #[test]
    fn build_addr_lo_v4_and_v6() {
        let mut buf = [0u8; 256];
        let end = nl_build_loopback_addr(&mut buf, 0, 256, 1, 1, libc::AF_INET, NLM_F_MULTI);
        let (_len, ty, _f, _s, _p) = hdr_fields(&buf, 0);
        assert_eq!(ty, RTM_NEWADDR);
        // ifaddrmsg: family=AF_INET, prefixlen=8, scope=host.
        assert_eq!(buf[16], libc::AF_INET as u8);
        assert_eq!(buf[17], 8);
        assert_eq!(buf[19], RT_SCOPE_HOST);
        assert!(end > 0);
        // v6: family AF_INET6, prefix 128.
        let end2 = nl_build_loopback_addr(&mut buf, 128, 256, 1, 1, libc::AF_INET6, NLM_F_MULTI);
        assert_eq!(buf[128 + 16], libc::AF_INET6 as u8);
        assert_eq!(buf[128 + 17], 128);
        assert!(end2 > 128);
    }

    #[test]
    fn request_is_loopback_detection() {
        // Empty request -> loopback.
        assert!(nl_request_is_loopback(&[]));
        // ifindex=1 -> loopback.
        let mut req = vec![0u8; NLMSG_HDR_LEN + 16];
        req[NLMSG_HDR_LEN + 4..NLMSG_HDR_LEN + 8].copy_from_slice(&1i32.to_ne_bytes());
        assert!(nl_request_is_loopback(&req));
        // ifindex=7 -> not loopback.
        req[NLMSG_HDR_LEN + 4..NLMSG_HDR_LEN + 8].copy_from_slice(&7i32.to_ne_bytes());
        assert!(!nl_request_is_loopback(&req));
        // IFLA_IFNAME "lo" overrides ifindex.
        let mut req = vec![0u8; NLMSG_HDR_LEN + 16 + 8];
        req[NLMSG_HDR_LEN + 4..NLMSG_HDR_LEN + 8].copy_from_slice(&7i32.to_ne_bytes());
        let aoff = NLMSG_HDR_LEN + 16;
        req[aoff..aoff + 2].copy_from_slice(&(rta_length(3) as u16).to_ne_bytes());
        req[aoff + 2..aoff + 4].copy_from_slice(&IFLA_IFNAME.to_ne_bytes());
        req[aoff + 4..aoff + 7].copy_from_slice(b"lo\0");
        assert!(nl_request_is_loopback(&req));
    }

    #[test]
    fn request_link_target_parses_name() {
        let mut req = vec![0u8; NLMSG_HDR_LEN + 16 + 12];
        req[NLMSG_HDR_LEN + 4..NLMSG_HDR_LEN + 8].copy_from_slice(&5i32.to_ne_bytes());
        let aoff = NLMSG_HDR_LEN + 16;
        req[aoff..aoff + 2].copy_from_slice(&(rta_length(5) as u16).to_ne_bytes());
        req[aoff + 2..aoff + 4].copy_from_slice(&IFLA_IFNAME.to_ne_bytes());
        req[aoff + 4..aoff + 9].copy_from_slice(b"eth0\0");
        let (idx, name) = nl_request_link_target(&req);
        assert_eq!(idx, 5);
        assert_eq!(&name[..5], b"eth0\0");
        // Truncated request -> zeros.
        assert_eq!(nl_request_link_target(&[]), (0, [0; 16]));
    }

    #[test]
    fn prefixlen_and_scope() {
        assert_eq!(nl_prefixlen(&[255, 255, 255, 0]), 24);
        assert_eq!(nl_prefixlen(&[255, 128, 0, 0]), 9);
        assert_eq!(nl_prefixlen(&[0, 0, 0, 0]), 0);
        assert_eq!(nl_prefixlen(&[255; 4]), 32);
        assert_eq!(nl_addr_scope(libc::AF_INET, &[127, 0, 0, 1]), RT_SCOPE_HOST);
        assert_eq!(
            nl_addr_scope(libc::AF_INET, &[169, 254, 1, 1]),
            RT_SCOPE_LINK
        );
        assert_eq!(
            nl_addr_scope(libc::AF_INET, &[8, 8, 8, 8]),
            RT_SCOPE_UNIVERSE
        );
        let lo6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
        assert_eq!(nl_addr_scope(libc::AF_INET6, &lo6), RT_SCOPE_HOST);
        let fe80 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
        assert_eq!(nl_addr_scope(libc::AF_INET6, &fe80), RT_SCOPE_LINK);
    }

    #[test]
    fn fake_fd_bookkeeping() {
        let mut t = test_tracee("/", &[]);
        t.fake_netlink_fds.push(FakeNetlinkSocket {
            fd: 7,
            reply: vec![0; MAX_FAKE_NETLINK_REPLY],
            reply_off: 0,
        });
        assert!(is_fake_netlink_fd(&t, 7));
        assert!(!is_fake_netlink_fd(&t, 8));
        assert!(!is_fake_netlink_fd(&t, -1));
        assert_eq!(fake_netlink_idx(&t, 7), Some(0));
        unmark_fake_netlink_fd(&mut t, 7);
        assert!(!is_fake_netlink_fd(&t, 7));
        // Route-fd bookkeeping + ack-pending reset.
        let mut t = test_tracee("/", &[]);
        t.netlink_route_fds.push(4);
        t.netlink_ack_pending = true;
        t.netlink_ack_fd = 4;
        assert!(is_netlink_route_fd(&t, 4));
        unmark_netlink_route_fd(&mut t, 4);
        assert!(!is_netlink_route_fd(&t, 4));
        assert!(!t.netlink_ack_pending);
    }

    #[test]
    fn fake_netlink_sockname_writes_nl() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee("/", &[]);
        t.pid = child.pid;
        // size_ptr at 0x900 (input capacity 16), addr at 0x800.
        let in_size = 16u32;
        arena.local()[0x900..0x904].copy_from_slice(&in_size.to_ne_bytes());
        assert_eq!(
            write_fake_netlink_sockname(&t, arena.addr() + 0x800, arena.addr() + 0x900, 77),
            0
        );
        // sockaddr_nl: family AF_NETLINK, pid 77, size out = 12.
        assert_eq!(
            u16::from_ne_bytes(arena.local()[0x800..0x802].try_into().unwrap()),
            libc::AF_NETLINK as u16
        );
        assert_eq!(
            u32::from_ne_bytes(arena.local()[0x804..0x808].try_into().unwrap()),
            77
        );
        assert_eq!(
            u32::from_ne_bytes(arena.local()[0x900..0x904].try_into().unwrap()),
            12
        );
        // size_ptr NULL -> EINVAL.
        assert_eq!(
            write_fake_netlink_sockname(&t, arena.addr() + 0x800, 0, 1),
            -libc::EINVAL
        );
    }

    #[test]
    fn msghdr_first_iovec_walks() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee("/", &[]);
        t.pid = child.pid;
        let w = crate::tracee::reg::sizeof_word(&t); // 8
        // iov at 0x500: {base=0x600, len=64}; msghdr at 0x700.
        arena.local()[0x500..0x508].copy_from_slice(&(arena.addr() + 0x600).to_ne_bytes());
        arena.local()[0x508..0x510].copy_from_slice(&64u64.to_ne_bytes());
        arena.local()[0x700 + 2 * w..0x700 + 2 * w + 8]
            .copy_from_slice(&(arena.addr() + 0x500).to_ne_bytes());
        arena.local()[0x700 + 3 * w..0x700 + 3 * w + 8].copy_from_slice(&1u64.to_ne_bytes());
        let (base, len) = msghdr_first_iovec(&t, arena.addr() + 0x700).unwrap();
        assert_eq!(base, arena.addr() + 0x600);
        assert_eq!(len, 64);
        // NULL msghdr / NULL iov -> None.
        assert!(msghdr_first_iovec(&t, 0).is_none());
        arena.local()[0x700 + 2 * w..0x700 + 2 * w + 8].copy_from_slice(&0u64.to_ne_bytes());
        assert!(msghdr_first_iovec(&t, arena.addr() + 0x700).is_none());
    }
}
