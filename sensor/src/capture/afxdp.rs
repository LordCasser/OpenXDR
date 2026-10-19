//! AF_XDP 抓包后端：绕过内核协议栈，直接从网卡队列取包。
//!
//! 结构：一块 UMEM（帧内存池）+ 四个环。
//!   FILL  用户态 → 内核：交出空闲帧供网卡填充
//!   RX    内核 → 用户态：收到的包
//!   TX / COMPLETION 本探针只收不发，建了但不用
//!
//! 收包前提是有 XDP 程序把包 redirect 到本 socket，见 ebpf/src/main.rs。
//! 一个 socket 对应一个网卡队列，多队列网卡需要每队列一个 worker。

use std::io;
use std::os::fd::RawFd;

use super::Capture;

const SOL_XDP: libc::c_int = 283;
const AF_XDP: libc::c_int = 44;
const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_RX_RING: libc::c_int = 2;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;

const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;

const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

#[repr(C)]
#[derive(Default)]
struct RingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct MmapOffsets {
    rx: RingOffset,
    tx: RingOffset,
    fill: RingOffset,
    completion: RingOffset,
}

#[repr(C)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

pub struct Config {
    /// UMEM 帧数，必须是 2 的幂
    pub frame_count: u32,
    pub frame_size: u32,
    pub queue_id: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            frame_count: 4096,
            frame_size: 2048,
            queue_id: 0,
        }
    }
}

/// 无锁单生产者/单消费者环的用户态视图。
struct Ring {
    producer: *mut u32,
    consumer: *mut u32,
    flags: *mut u32,
    desc: *mut u8,
    mask: u32,
    cached_consumer: u32,
}

impl Ring {
    unsafe fn new(base: *mut u8, off: &RingOffset, size: u32) -> Self {
        unsafe {
            Self {
                producer: base.add(off.producer as usize) as *mut u32,
                consumer: base.add(off.consumer as usize) as *mut u32,
                flags: base.add(off.flags as usize) as *mut u32,
                desc: base.add(off.desc as usize),
                mask: size - 1,
                cached_consumer: 0,
            }
        }
    }

    fn producer_value(&self) -> u32 {
        unsafe { std::ptr::read_volatile(self.producer) }
    }

    fn needs_wakeup(&self) -> bool {
        unsafe { std::ptr::read_volatile(self.flags) & XDP_RING_NEED_WAKEUP != 0 }
    }

    /// 生产者侧（FILL 环）：从当前 producer 起依次写入帧地址，再发布新的 producer。
    /// 调用方保证 addrs 不超过环上的空闲槽数。
    fn publish(&mut self, addrs: &[u64]) {
        let producer = self.producer_value();
        for (i, addr) in addrs.iter().enumerate() {
            let slot = (producer.wrapping_add(i as u32) & self.mask) as usize;
            unsafe { std::ptr::write((self.desc as *mut u64).add(slot), *addr) };
        }
        unsafe {
            std::ptr::write_volatile(self.producer, producer.wrapping_add(addrs.len() as u32))
        };
    }

    /// 消费者侧（RX 环）：取走 [cached_consumer, producer) 的描述符，对每帧调用 `f`，
    /// 发布新的 consumer，返回取走的帧地址（之后还给 FILL 环）。
    ///
    /// # Safety
    /// `self` 必须是 RX 环（desc 为 XdpDesc 数组）；`umem` 指向本 socket 注册的 UMEM，
    /// 且内核填进描述符的每个 addr + len 都落在 UMEM 内。
    unsafe fn consume(
        &mut self,
        umem: *const u8,
        producer: u32,
        f: &mut dyn FnMut(&[u8]),
    ) -> Vec<u64> {
        let mut consumer = self.cached_consumer;
        let mut used = Vec::with_capacity((producer.wrapping_sub(consumer)) as usize);
        while consumer != producer {
            let slot = (consumer & self.mask) as usize;
            let desc = unsafe { &*(self.desc as *const XdpDesc).add(slot) };
            let frame = unsafe {
                std::slice::from_raw_parts(umem.add(desc.addr as usize), desc.len as usize)
            };
            f(frame);
            used.push(desc.addr);
            consumer = consumer.wrapping_add(1);
        }

        unsafe { std::ptr::write_volatile(self.consumer, consumer) };
        self.cached_consumer = consumer;
        used
    }
}

pub struct AfXdp {
    fd: RawFd,
    umem: *mut u8,
    umem_len: usize,
    rx_map: *mut u8,
    rx_map_len: usize,
    fill_map: *mut u8,
    fill_map_len: usize,
    comp_map: *mut u8,
    comp_map_len: usize,
    rx: Ring,
    fill: Ring,
    frame_size: u32,
    frame_count: u32,
    dropped: u64,
}

unsafe impl Send for AfXdp {}

impl AfXdp {
    pub fn open(iface: &str, cfg: &Config) -> io::Result<Self> {
        assert!(
            cfg.frame_count.is_power_of_two(),
            "frame_count 必须是 2 的幂"
        );

        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // UMEM：页对齐的连续内存，网卡直接往里 DMA
        let umem_len = (cfg.frame_count * cfg.frame_size) as usize;
        let umem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                umem_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if umem == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        let umem = umem as *mut u8;

        let reg = XdpUmemReg {
            addr: umem as u64,
            len: umem_len as u64,
            chunk_size: cfg.frame_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt(fd, XDP_UMEM_REG, &reg)?;
        setsockopt(fd, XDP_UMEM_FILL_RING, &cfg.frame_count)?;
        setsockopt(fd, XDP_UMEM_COMPLETION_RING, &cfg.frame_count)?;
        setsockopt(fd, XDP_RX_RING, &cfg.frame_count)?;

        let offsets = mmap_offsets(fd)?;
        let (rx_map, rx_map_len) = map_ring(
            fd,
            XDP_PGOFF_RX_RING,
            offsets.rx.desc as usize + cfg.frame_count as usize * size_of::<XdpDesc>(),
        )?;
        let (fill_map, fill_map_len) = map_ring(
            fd,
            XDP_UMEM_PGOFF_FILL_RING,
            offsets.fill.desc as usize + cfg.frame_count as usize * size_of::<u64>(),
        )?;
        let (comp_map, comp_map_len) = map_ring(
            fd,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            offsets.completion.desc as usize + cfg.frame_count as usize * size_of::<u64>(),
        )?;

        let rx = unsafe { Ring::new(rx_map, &offsets.rx, cfg.frame_count) };
        let fill = unsafe { Ring::new(fill_map, &offsets.fill, cfg.frame_count) };

        let index = if_index(iface)?;
        let addr = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: index,
            sxdp_queue_id: cfg.queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut this = Self {
            fd,
            umem,
            umem_len,
            rx_map,
            rx_map_len,
            fill_map,
            fill_map_len,
            comp_map,
            comp_map_len,
            rx,
            fill,
            frame_size: cfg.frame_size,
            frame_count: cfg.frame_count,
            dropped: 0,
        };
        this.fill_all();
        Ok(this)
    }

    /// 把所有帧交给内核，网卡才有地方放包。
    fn fill_all(&mut self) {
        let producer = self.fill.producer_value();
        for i in 0..self.frame_count {
            let slot = (producer.wrapping_add(i) & self.fill.mask) as usize;
            unsafe {
                let addr = self.fill.desc as *mut u64;
                std::ptr::write(addr.add(slot), (i * self.frame_size) as u64);
            }
        }
        unsafe {
            std::ptr::write_volatile(self.fill.producer, producer.wrapping_add(self.frame_count))
        };
    }

    /// 把消费完的帧还给 FILL 环，否则网卡很快无帧可用。
    fn recycle(&mut self, addrs: &[u64]) {
        if addrs.is_empty() {
            return;
        }
        self.fill.publish(addrs);
    }

    /// NEED_WAKEUP 模式下内核可能在休眠，要用 poll 叫醒它继续填包。
    fn wait(&self) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        if pfd.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
            return Err(io::Error::other(format!(
                "AF_XDP 套接字异常: revents={:#x}",
                pfd.revents
            )));
        }
        Ok(n > 0)
    }
}

impl Capture for AfXdp {
    fn poll_batch(&mut self, f: &mut dyn FnMut(&[u8], u64)) -> io::Result<usize> {
        let producer = self.rx.producer_value();
        let consumer = self.rx.cached_consumer;
        if consumer == producer {
            if self.fill.needs_wakeup() && !self.wait()? {
                return Ok(0);
            }
            let producer = self.rx.producer_value();
            if consumer == producer {
                return Ok(0);
            }
        }

        let producer = self.rx.producer_value();
        // AF_XDP 不提供硬件时间戳，用接收时刻代替
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let used = unsafe {
            self.rx
                .consume(self.umem, producer, &mut |frame| f(frame, now_ns))
        };
        let count = used.len();
        self.recycle(&used);
        Ok(count)
    }

    fn dropped(&self) -> u64 {
        // 内核不通过 socket 选项暴露 XDP 丢包，这里只统计本进程可见的部分
        self.dropped
    }
}

impl std::os::fd::AsRawFd for AfXdp {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for AfXdp {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.rx_map as *mut libc::c_void, self.rx_map_len);
            libc::munmap(self.fill_map as *mut libc::c_void, self.fill_map_len);
            libc::munmap(self.comp_map as *mut libc::c_void, self.comp_map_len);
            libc::munmap(self.umem as *mut libc::c_void, self.umem_len);
            libc::close(self.fd);
        }
    }
}

fn mmap_offsets(fd: RawFd) -> io::Result<MmapOffsets> {
    let mut offsets = MmapOffsets::default();
    let mut len = size_of::<MmapOffsets>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut offsets as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(offsets)
}

fn map_ring(fd: RawFd, offset: libc::off_t, len: usize) -> io::Result<(*mut u8, usize)> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            offset,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok((ptr as *mut u8, len))
}

fn setsockopt<T>(fd: RawFd, opt: libc::c_int, value: &T) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
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

fn if_index(iface: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "网卡名含 NUL"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{ManuallyDrop, offset_of};

    const N: u32 = 4;
    const FRAME: u32 = 2048;
    /// 仿内核的环布局：producer / consumer / flags 各占一条缓存行，描述符数组在后
    const OFF: RingOffset = RingOffset {
        producer: 0,
        consumer: 64,
        flags: 128,
        desc: 192,
    };

    /// 8 字节对齐的堆内存充当 mmap 出来的环
    struct Mem(Vec<u64>);

    impl Mem {
        fn new(bytes: usize) -> Self {
            Self(vec![0; bytes.div_ceil(8)])
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr().cast()
        }

        fn ring(&mut self) -> Ring {
            // SAFETY: 内存足够容纳 OFF 布局下 N 个描述符，偏移均按 4/8 字节对齐，测试期间不释放
            unsafe { Ring::new(self.ptr(), &OFF, N) }
        }

        fn u32_at(&mut self, off: u64) -> u32 {
            // SAFETY: off 是 OFF 中的 4 字节对齐偏移，落在 Mem 内
            unsafe { std::ptr::read(self.ptr().add(off as usize).cast::<u32>()) }
        }

        fn set_u32(&mut self, off: u64, v: u32) {
            // SAFETY: 同上
            unsafe { std::ptr::write(self.ptr().add(off as usize).cast::<u32>(), v) }
        }

        fn fill_slots(&mut self) -> Vec<u64> {
            (0..N as usize)
                .map(|i| self.0[OFF.desc as usize / 8 + i])
                .collect()
        }

        fn put(&mut self, at: usize, bytes: &[u8]) {
            assert!(at + bytes.len() <= self.0.len() * 8);
            // SAFETY: 上面已校验 [at, at + len) 落在 Mem 内；u8 无对齐要求
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr().add(at), bytes.len())
            }
        }

        fn set_rx_desc(&mut self, slot: u32, addr: u64, len: u32) {
            let at = OFF.desc as usize + slot as usize * size_of::<XdpDesc>();
            let desc = XdpDesc {
                addr,
                len,
                options: 0,
            };
            // SAFETY: slot < N，描述符落在 RX 环内；OFF.desc 为 8 的倍数，满足 XdpDesc 对齐
            unsafe { std::ptr::write(self.ptr().add(at).cast::<XdpDesc>(), desc) }
        }
    }

    fn rx_mem() -> Mem {
        Mem::new(OFF.desc as usize + N as usize * size_of::<XdpDesc>())
    }

    fn fill_mem() -> Mem {
        Mem::new(OFF.desc as usize + N as usize * size_of::<u64>())
    }

    #[test]
    fn uapi_struct_layout() {
        // 与 linux/if_xdp.h 一致
        assert_eq!(size_of::<XdpDesc>(), 16);
        assert_eq!(offset_of!(XdpDesc, len), 8);
        assert_eq!(size_of::<SockaddrXdp>(), 16);
        assert_eq!(size_of::<XdpUmemReg>(), 32);
        assert_eq!(size_of::<MmapOffsets>(), 4 * 32);
        assert_eq!(offset_of!(MmapOffsets, fill), 64);
    }

    #[test]
    fn ring_view_points_into_mapping() {
        let mut mem = fill_mem();
        let base = mem.ptr();
        let ring = mem.ring();
        assert_eq!(ring.mask, N - 1);
        assert_eq!(ring.producer as usize - base as usize, 0);
        assert_eq!(ring.consumer as usize - base as usize, 64);
        assert_eq!(ring.flags as usize - base as usize, 128);
        assert_eq!(ring.desc as usize - base as usize, 192);
        assert_eq!(ring.cached_consumer, 0);
    }

    #[test]
    fn needs_wakeup_reads_flag_bit() {
        let mut mem = fill_mem();
        let ring = mem.ring();
        assert!(!ring.needs_wakeup());
        mem.set_u32(OFF.flags, XDP_RING_NEED_WAKEUP);
        assert!(ring.needs_wakeup());
        mem.set_u32(OFF.flags, !XDP_RING_NEED_WAKEUP);
        assert!(!ring.needs_wakeup());
    }

    #[test]
    fn publish_wraps_slots_and_producer() {
        let mut mem = fill_mem();
        let mut ring = mem.ring();
        // producer 停在 u32 上限前两格：槽号按掩码回绕，producer 本身也按 u32 回绕
        mem.set_u32(OFF.producer, u32::MAX - 1);
        ring.publish(&[10, 20, 30]);
        assert_eq!(mem.u32_at(OFF.producer), 1);
        // (MAX-1)&3 = 2，MAX&3 = 3，0&3 = 0
        assert_eq!(mem.fill_slots(), [30, 0, 10, 20]);

        ring.publish(&[]);
        assert_eq!(mem.u32_at(OFF.producer), 1, "空批次不动 producer");
    }

    #[test]
    fn consume_reads_frames_and_publishes_consumer() {
        let mut umem = Mem::new((N * FRAME) as usize);
        for i in 0..N as usize {
            umem.put(i * FRAME as usize, format!("frame-{i}").as_bytes());
        }
        let mut mem = rx_mem();
        let mut ring = mem.ring();
        // 从回绕边界前一格开始消费两帧：槽 3 与槽 0
        ring.cached_consumer = u32::MAX;
        mem.set_rx_desc(3, 2 * FRAME as u64, 7);
        mem.set_rx_desc(0, 0, 5);
        let mut seen = Vec::new();
        // SAFETY: 描述符的 addr + len 都在 umem 内
        let used = unsafe { ring.consume(umem.ptr(), 1, &mut |f: &[u8]| seen.push(f.to_vec())) };
        assert_eq!(seen, [b"frame-2".to_vec(), b"frame".to_vec()]);
        assert_eq!(used, [2 * FRAME as u64, 0]);
        assert_eq!(ring.cached_consumer, 1);
        assert_eq!(mem.u32_at(OFF.consumer), 1);
    }

    #[test]
    fn consume_with_nothing_pending_is_empty() {
        let umem = Mem::new(FRAME as usize);
        let mut mem = rx_mem();
        let mut ring = mem.ring();
        ring.cached_consumer = 7;
        let mut calls = 0;
        // SAFETY: 没有待取描述符，不会访问 umem
        let used = unsafe { ring.consume(umem.0.as_ptr().cast(), 7, &mut |_| calls += 1) };
        assert!(used.is_empty());
        assert_eq!(calls, 0);
        assert_eq!(mem.u32_at(OFF.consumer), 7);
    }

    /// 不经 open 拼出一个指向假环的 AfXdp。ManuallyDrop 防止 Drop 去 munmap 堆内存、close(-1)
    fn fake_socket(umem: &mut Mem, rx: &mut Mem, fill: &mut Mem) -> ManuallyDrop<AfXdp> {
        ManuallyDrop::new(AfXdp {
            fd: -1,
            umem: umem.ptr(),
            umem_len: (N * FRAME) as usize,
            rx_map: rx.ptr(),
            rx_map_len: 0,
            fill_map: fill.ptr(),
            fill_map_len: 0,
            comp_map: std::ptr::null_mut(),
            comp_map_len: 0,
            rx: rx.ring(),
            fill: fill.ring(),
            frame_size: FRAME,
            frame_count: N,
            dropped: 0,
        })
    }

    #[test]
    fn fill_all_hands_every_frame_to_kernel() {
        let (mut umem, mut rx, mut fill) = (Mem::new((N * FRAME) as usize), rx_mem(), fill_mem());
        let mut sock = fake_socket(&mut umem, &mut rx, &mut fill);
        sock.fill_all();
        assert_eq!(fill.fill_slots(), [0, 2048, 4096, 6144]);
        assert_eq!(fill.u32_at(OFF.producer), N);
    }

    #[test]
    fn poll_batch_recycles_consumed_frames() {
        let (mut umem, mut rx, mut fill) = (Mem::new((N * FRAME) as usize), rx_mem(), fill_mem());
        let mut sock = fake_socket(&mut umem, &mut rx, &mut fill);
        sock.fill_all();
        // 内核收了两帧：放在第 1、3 帧，producer 前进 2
        rx.set_rx_desc(0, FRAME as u64, 60);
        rx.set_rx_desc(1, 3 * FRAME as u64, 1514);
        rx.set_u32(OFF.producer, 2);

        let mut lens = Vec::new();
        let n = sock
            .poll_batch(&mut |f, ts| lens.push((f.len(), ts > 0)))
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(lens, [(60, true), (1514, true)]);
        assert_eq!(rx.u32_at(OFF.consumer), 2);
        // 用过的帧按消费顺序回到 FILL 环，接在 fill_all 的 4 帧之后（槽号回绕到 0、1）
        assert_eq!(fill.u32_at(OFF.producer), N + 2);
        assert_eq!(fill.fill_slots(), [2048, 6144, 4096, 6144]);
    }

    #[test]
    fn poll_batch_without_new_frames_returns_zero() {
        let (mut umem, mut rx, mut fill) = (Mem::new((N * FRAME) as usize), rx_mem(), fill_mem());
        let mut sock = fake_socket(&mut umem, &mut rx, &mut fill);
        // 内核未要求唤醒：不 poll，直接返回 0
        assert_eq!(sock.poll_batch(&mut |_, _| unreachable!()).unwrap(), 0);
        assert_eq!(fill.u32_at(OFF.producer), 0);
    }
}
