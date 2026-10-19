//! AF_PACKET v3 (TPACKET_V3) 抓包环。
//!
//! 内核把帧写进 mmap 共享的块（block）环形缓冲，用户态按块批量消费——
//! 每块一次同步，而不是每包一次，这是 v3 相对 v2 的核心优势。
//! PACKET_FANOUT_HASH 保证同一条流恒定落到同一 worker，流表因此无需加锁。

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use super::Capture;

const TPACKET_V3: libc::c_int = 2;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_VERSION: libc::c_int = 10;
const PACKET_FANOUT: libc::c_int = 18;
const PACKET_FANOUT_HASH: libc::c_uint = 0;
/// 让内核在分发前重组 IP 分片。除了拿到完整数据报，
/// 还顺带解决了非首片没有端口、哈希后被散到别的 worker 的问题。
const PACKET_FANOUT_FLAG_DEFRAG: libc::c_uint = 0x8000;
const TP_STATUS_USER: u32 = 1 << 0;

#[repr(C)]
struct TpacketReq3 {
    tp_block_size: libc::c_uint,
    tp_block_nr: libc::c_uint,
    tp_frame_size: libc::c_uint,
    tp_frame_nr: libc::c_uint,
    tp_retire_blk_tov: libc::c_uint,
    tp_sizeof_priv: libc::c_uint,
    tp_feature_req_word: libc::c_uint,
}

/// 对应内核 struct tpacket_block_desc：前两个字段是 version 和 offset_to_priv，
/// 之后才是 tpacket_hdr_v1。少了这 8 字节会把 version 当成 block_status 读。
#[repr(C)]
struct BlockDescV1 {
    version: u32,
    offset_to_priv: u32,
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBdTs,
    ts_last_pkt: TpacketBdTs,
}

#[repr(C)]
struct TpacketBdTs {
    ts_sec: u32,
    ts_nsec: u32,
}

#[repr(C)]
struct Tpacket3Hdr {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    // 后续还有 hv1 union，我们用不到
}

#[repr(C)]
struct TpacketStatsV3 {
    tp_packets: libc::c_uint,
    tp_drops: libc::c_uint,
    tp_freeze_q_cnt: libc::c_uint,
}

pub struct RingConfig {
    pub block_size: u32,
    pub block_count: u32,
    /// 块超时（毫秒）：块未满也会在此时限后交给用户态，控制延迟
    pub block_timeout_ms: u32,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            block_size: 1 << 21, // 2 MiB
            block_count: 64,     // 共 128 MiB
            block_timeout_ms: 100,
        }
    }
}

pub struct AfPacket {
    fd: RawFd,
    ring: *mut u8,
    ring_len: usize,
    block_size: usize,
    block_count: usize,
    next_block: usize,
}

// ring 指针指向本 fd 私有的 mmap 区域，随结构体一起移动到 worker 线程
unsafe impl Send for AfPacket {}

impl AfPacket {
    /// 在 `iface` 上开一个抓包环。`fanout_group` 非 0 时加入 FANOUT 组，
    /// 同组的多个 socket 按流哈希分担流量。
    pub fn open(iface: &str, cfg: &RingConfig, fanout_group: u16) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let guard = FdGuard(fd);

        setsockopt(fd, PACKET_VERSION, &TPACKET_V3)?;

        // frame_size 设成 block_size：v3 下帧在块内自由排布，此值仅用于合法性校验
        let req = TpacketReq3 {
            tp_block_size: cfg.block_size,
            tp_block_nr: cfg.block_count,
            tp_frame_size: cfg.block_size,
            tp_frame_nr: cfg.block_count,
            tp_retire_blk_tov: cfg.block_timeout_ms,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        setsockopt(fd, PACKET_RX_RING, &req)?;

        let ring_len = cfg.block_size as usize * cfg.block_count as usize;
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_LOCKED,
                fd,
                0,
            )
        };
        if ring == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        bind_iface(fd, iface)?;

        if fanout_group != 0 {
            let group = fanout_group as libc::c_uint;
            let with_defrag = group | ((PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG) << 16);
            // 老内核不支持 DEFRAG 标志，退回普通哈希分发（分片会丢，但不影响主流量）
            if setsockopt(fd, PACKET_FANOUT, &with_defrag).is_err() {
                eprintln!("内核不支持 AF_PACKET 分片重组，IP 分片将被跳过");
                setsockopt(fd, PACKET_FANOUT, &(group | (PACKET_FANOUT_HASH << 16)))?;
            }
        }

        std::mem::forget(guard);
        Ok(Self {
            fd,
            ring: ring as *mut u8,
            ring_len,
            block_size: cfg.block_size as usize,
            block_count: cfg.block_count as usize,
            next_block: 0,
        })
    }

    fn block_ptr(&self, index: usize) -> *mut BlockDescV1 {
        unsafe { self.ring.add(index * self.block_size) as *mut BlockDescV1 }
    }

    /// 等待当前块就绪。返回 false 表示超时（无数据）。
    fn wait_block(&self) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if pfd.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
                return Err(io::Error::other(format!(
                    "抓包套接字异常: revents={:#x}",
                    pfd.revents
                )));
            }
            return Ok(n > 0);
        }
    }
}

impl Capture for AfPacket {
    fn poll_batch(&mut self, f: &mut dyn FnMut(&[u8], u64)) -> io::Result<usize> {
        let desc = self.block_ptr(self.next_block);

        // 内核写完整块才置 TP_STATUS_USER；未就绪就 poll 等。
        // poll 可能报可读但当前块尚未retire，限次让出，避免空转饿死上层的老化与统计。
        let mut attempts = 0;
        while unsafe { std::ptr::read_volatile(&(*desc).block_status) } & TP_STATUS_USER == 0 {
            if !self.wait_block()? {
                return Ok(0);
            }
            attempts += 1;
            if attempts >= 8 {
                return Ok(0);
            }
        }

        let num_pkts = unsafe { walk_block(desc, f) };

        // 归还块给内核
        unsafe { std::ptr::write_volatile(&mut (*desc).block_status, 0) };
        self.next_block = (self.next_block + 1) % self.block_count;
        Ok(num_pkts as usize)
    }

    fn dropped(&self) -> u64 {
        let mut stats = TpacketStatsV3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };
        let mut len = size_of::<TpacketStatsV3>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut stats as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 { 0 } else { stats.tp_drops as u64 }
    }
}

/// 遍历一个已交给用户态的块，对每帧调用 `f`，返回块头声明的包数。
///
/// # Safety
/// `desc` 必须指向一个完整、可读的 TPACKET_V3 块（块头 + 帧数据），且块内各帧的
/// 偏移、mac 偏移与 snaplen 都落在块内；遍历期间块内容不被并发改写（内核置了
/// TP_STATUS_USER 之后、用户态归还之前即是如此）。块头与帧头须按 4 字节对齐。
unsafe fn walk_block(desc: *const BlockDescV1, f: &mut dyn FnMut(&[u8], u64)) -> u32 {
    let (num_pkts, first_offset) = unsafe { ((*desc).num_pkts, (*desc).offset_to_first_pkt) };
    let block_base = desc as *const u8;
    let mut offset = first_offset as usize;

    for _ in 0..num_pkts {
        let hdr = unsafe { block_base.add(offset) as *const Tpacket3Hdr };
        let (next, mac, snaplen, sec, nsec) = unsafe {
            (
                (*hdr).tp_next_offset as usize,
                (*hdr).tp_mac as usize,
                (*hdr).tp_snaplen as usize,
                (*hdr).tp_sec as u64,
                (*hdr).tp_nsec as u64,
            )
        };
        // 零拷贝：帧数据直接借用 mmap 区域
        let frame = unsafe { std::slice::from_raw_parts(block_base.add(offset + mac), snaplen) };
        f(frame, sec * 1_000_000_000 + nsec);

        if next == 0 {
            break;
        }
        offset += next;
    }
    num_pkts
}

impl AsRawFd for AfPacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for AfPacket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring as *mut libc::c_void, self.ring_len);
            libc::close(self.fd);
        }
    }
}

struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn setsockopt<T>(fd: RawFd, opt: libc::c_int, value: &T) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            opt,
            value as *const T as *const libc::c_void,
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_iface(fd: RawFd, iface: &str) -> io::Result<()> {
    let name = std::ffi::CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "网卡名含 NUL"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = index as i32;

    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{ManuallyDrop, offset_of};

    const BLOCK: usize = 4096;
    const FIRST: usize = 48;

    /// 用 8 字节对齐的堆内存模拟 mmap 环：块头与帧头按内核布局逐字段写进去
    struct FakeRing(Vec<u64>);

    impl FakeRing {
        fn new(blocks: usize) -> Self {
            Self(vec![0; blocks * BLOCK / 8])
        }

        fn bytes(&mut self) -> &mut [u8] {
            let len = self.0.len() * 8;
            // SAFETY: Vec<u64> 的缓冲区是 len 个已初始化字节，u8 无对齐要求，借用期间独占
            unsafe { std::slice::from_raw_parts_mut(self.0.as_mut_ptr().cast(), len) }
        }

        fn put_u32(&mut self, at: usize, v: u32) {
            self.bytes()[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        }

        fn put_u16(&mut self, at: usize, v: u16) {
            self.bytes()[at..at + 2].copy_from_slice(&v.to_ne_bytes());
        }

        fn status(&mut self, block: usize) -> u32 {
            let at = block * BLOCK + offset_of!(BlockDescV1, block_status);
            u32::from_ne_bytes(self.bytes()[at..at + 4].try_into().unwrap())
        }

        /// 写一个就绪块：frames 为（mac 偏移、帧数据、线上长度、秒、纳秒），帧头按 next 链接
        fn block(&mut self, block: usize, num_pkts: u32, frames: &[(u16, &[u8], u32, u32, u32)]) {
            let base = block * BLOCK;
            self.put_u32(base + offset_of!(BlockDescV1, block_status), TP_STATUS_USER);
            self.put_u32(base + offset_of!(BlockDescV1, num_pkts), num_pkts);
            self.put_u32(
                base + offset_of!(BlockDescV1, offset_to_first_pkt),
                FIRST as u32,
            );
            let mut off = FIRST;
            for (i, (mac, data, len, sec, nsec)) in frames.iter().enumerate() {
                let hdr = base + off;
                let size = (*mac as usize + data.len()).next_multiple_of(16);
                let next = if i + 1 == frames.len() {
                    0
                } else {
                    size as u32
                };
                self.put_u32(hdr + offset_of!(Tpacket3Hdr, tp_next_offset), next);
                self.put_u32(hdr + offset_of!(Tpacket3Hdr, tp_sec), *sec);
                self.put_u32(hdr + offset_of!(Tpacket3Hdr, tp_nsec), *nsec);
                self.put_u32(hdr + offset_of!(Tpacket3Hdr, tp_snaplen), data.len() as u32);
                self.put_u32(hdr + offset_of!(Tpacket3Hdr, tp_len), *len);
                self.put_u16(hdr + offset_of!(Tpacket3Hdr, tp_mac), *mac);
                let at = hdr + *mac as usize;
                self.bytes()[at..at + data.len()].copy_from_slice(data);
                off += size;
            }
        }

        fn walk(&mut self, block: usize) -> (u32, Vec<(Vec<u8>, u64)>) {
            let mut seen = Vec::new();
            let desc = self.bytes()[block * BLOCK..].as_ptr().cast::<BlockDescV1>();
            // SAFETY: desc 指向本测试按内核布局构造的完整块，偏移都在块内，8 字节对齐
            let n = unsafe { walk_block(desc, &mut |f, ts| seen.push((f.to_vec(), ts))) };
            (n, seen)
        }
    }

    #[test]
    fn kernel_struct_layout() {
        // 与 linux/if_packet.h 一致：块头 48 字节，帧头前 28 字节
        assert_eq!(offset_of!(BlockDescV1, block_status), 8);
        assert_eq!(offset_of!(BlockDescV1, num_pkts), 12);
        assert_eq!(offset_of!(BlockDescV1, offset_to_first_pkt), 16);
        assert_eq!(offset_of!(BlockDescV1, seq_num), 24);
        assert_eq!(size_of::<BlockDescV1>(), 48);
        assert_eq!(offset_of!(Tpacket3Hdr, tp_snaplen), 12);
        assert_eq!(offset_of!(Tpacket3Hdr, tp_mac), 24);
        assert_eq!(size_of::<Tpacket3Hdr>(), 28);
        assert_eq!(size_of::<TpacketReq3>(), 28);
        assert_eq!(size_of::<TpacketStatsV3>(), 12);
    }

    #[test]
    fn walks_chained_frames_with_timestamps() {
        let mut ring = FakeRing::new(1);
        ring.block(
            0,
            3,
            &[
                (32, b"first", 5, 1, 2),
                (34, b"second-frame", 12, 10, 999_999_999),
                (32, b"x", 1, u32::MAX, 0),
            ],
        );
        let (n, seen) = ring.walk(0);
        assert_eq!(n, 3);
        assert_eq!(
            seen,
            [
                (b"first".to_vec(), 1_000_000_002),
                (b"second-frame".to_vec(), 10_999_999_999),
                (b"x".to_vec(), u32::MAX as u64 * 1_000_000_000),
            ]
        );
    }

    #[test]
    fn frame_length_is_snaplen_not_wire_length() {
        // 被 snaplen 截短的帧只交付抓到的部分；snaplen 为 0 交付空帧
        let mut ring = FakeRing::new(1);
        ring.block(0, 2, &[(32, b"head", 1500, 0, 0), (32, b"", 60, 0, 0)]);
        let (_, seen) = ring.walk(0);
        assert_eq!(seen[0].0, b"head");
        assert!(seen[1].0.is_empty());
    }

    #[test]
    fn empty_block_delivers_nothing() {
        let mut ring = FakeRing::new(1);
        ring.block(0, 0, &[]);
        assert_eq!(ring.walk(0), (0, vec![]));
    }

    #[test]
    fn next_offset_zero_ends_block_early() {
        // 块头声明的包数多于链上实际的帧：以 next == 0 为准停下，返回值仍是块头的包数
        let mut ring = FakeRing::new(1);
        ring.block(0, 5, &[(32, b"only", 4, 0, 0)]);
        let (n, seen) = ring.walk(0);
        assert_eq!(n, 5);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn num_pkts_caps_walk_even_if_chain_continues() {
        let mut ring = FakeRing::new(1);
        ring.block(
            0,
            2,
            &[
                (32, b"a", 1, 0, 0),
                (32, b"b", 1, 0, 0),
                (32, b"c", 1, 0, 0),
            ],
        );
        let (n, seen) = ring.walk(0);
        assert_eq!(n, 2);
        let frames: Vec<_> = seen.into_iter().map(|s| s.0).collect();
        assert_eq!(frames, [b"a", b"b"]);
    }

    /// 不经 open 拼出一个指向假环的 AfPacket。ManuallyDrop 防止 Drop 去 munmap 堆内存、close(-1)
    fn fake_capture(ring: &mut FakeRing, blocks: usize) -> ManuallyDrop<AfPacket> {
        ManuallyDrop::new(AfPacket {
            fd: -1,
            ring: ring.bytes().as_mut_ptr(),
            ring_len: blocks * BLOCK,
            block_size: BLOCK,
            block_count: blocks,
            next_block: 0,
        })
    }

    #[test]
    fn poll_batch_returns_blocks_and_wraps_index() {
        let mut ring = FakeRing::new(2);
        ring.block(0, 1, &[(32, b"b0", 2, 0, 0)]);
        ring.block(1, 2, &[(32, b"b1a", 3, 0, 0), (32, b"b1b", 3, 0, 0)]);
        let mut cap = fake_capture(&mut ring, 2);
        let mut seen = Vec::new();
        let mut sink = |f: &[u8], _| seen.push(f.to_vec());

        assert_eq!(cap.poll_batch(&mut sink).unwrap(), 1);
        assert_eq!(cap.next_block, 1);
        assert_eq!(cap.poll_batch(&mut sink).unwrap(), 2);
        assert_eq!(cap.next_block, 0, "最后一块之后回到第 0 块");
        assert_eq!(seen, [b"b0".to_vec(), b"b1a".to_vec(), b"b1b".to_vec()]);
        // 消费完的块状态清零，归还内核
        assert_eq!(ring.status(0), 0);
        assert_eq!(ring.status(1), 0);
    }

    #[test]
    fn poll_batch_on_unready_block_does_not_advance() {
        // 块未就绪时去 poll(fd = -1)：负 fd 被忽略，等满 1 秒超时返回 0，不动块序号
        let mut ring = FakeRing::new(2);
        let mut cap = fake_capture(&mut ring, 2);
        let mut calls = 0;
        assert_eq!(cap.poll_batch(&mut |_, _| calls += 1).unwrap(), 0);
        assert_eq!(cap.next_block, 0);
        assert_eq!(calls, 0);
    }
}
