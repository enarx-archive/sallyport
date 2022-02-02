// SPDX-License-Identifier: Apache-2.0

use crate::guest::alloc::Collector;
use crate::guest::Stub;
use crate::Result;

use core::mem;
use libc::{
    c_char, c_int, c_uint, gid_t, pid_t, sigset_t, size_t, stack_t, stat, uid_t, utsname, EBADFD,
    STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, S_IFIFO,
};

/// Fake GID returned by enarx.
pub const FAKE_GID: gid_t = 1000;

/// Fake PID returned by enarx.
pub const FAKE_PID: pid_t = 1000;

/// Fake TID returned by enarx.
pub const FAKE_TID: pid_t = 1;

/// Fake UID returned by enarx.
pub const FAKE_UID: uid_t = 1000;

pub struct Fstat<'a> {
    pub fd: c_int,
    pub statbuf: &'a mut stat,
}

impl<'a> Stub for Fstat<'a> {
    type Ret = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        match self.fd {
            STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO => {
                #[allow(clippy::integer_arithmetic)]
                const fn makedev(x: u64, y: u64) -> u64 {
                    (((x) & 0xffff_f000u64) << 32)
                        | (((x) & 0x0000_0fffu64) << 8)
                        | (((y) & 0xffff_ff00u64) << 12)
                        | ((y) & 0x0000_00ffu64)
                }

                let mut p: stat = unsafe { mem::zeroed() };

                p.st_dev = makedev(
                    0,
                    match self.fd {
                        0 => 0x19,
                        _ => 0xc,
                    },
                );
                p.st_ino = 3;
                p.st_mode = S_IFIFO | 0o600;
                p.st_nlink = 1;
                p.st_uid = 1000;
                p.st_gid = 5;
                p.st_blksize = 4096;
                p.st_blocks = 0;
                p.st_rdev = makedev(0x88, 0);
                p.st_size = 0;

                p.st_atime = 1_579_507_218 /* 2020-01-21T11:45:08.467721685+0100 */;
                p.st_atime_nsec = 0;
                p.st_mtime = 1_579_507_218 /* 2020-01-21T11:45:07.467721685+0100 */;
                p.st_mtime_nsec = 0;
                p.st_ctime = 1_579_507_218 /* 2020-01-20T09:00:18.467721685+0100 */;
                p.st_ctime_nsec = 0;

                *self.statbuf = p;
                Ok(())
            }
            // TODO: Support `fstat` on files.
            // https://github.com/enarx/sallyport/issues/45
            _ => Err(EBADFD),
        }
    }
}

pub struct Getegid;

impl Stub for Getegid {
    type Ret = gid_t;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        FAKE_GID
    }
}

pub struct Geteuid;

impl Stub for Geteuid {
    type Ret = uid_t;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        FAKE_UID
    }
}

pub struct Getgid;

impl Stub for Getgid {
    type Ret = gid_t;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        FAKE_GID
    }
}

pub struct Getpid;

impl Stub for Getpid {
    type Ret = pid_t;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        FAKE_PID
    }
}

pub struct Getrandom<'a> {
    pub buf: &'a mut [u8],
    pub flags: c_uint,
}

impl Stub for Getrandom<'_> {
    type Ret = Result<size_t>;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        let flags = self.flags & !(libc::GRND_NONBLOCK | libc::GRND_RANDOM);
        if flags != 0 {
            return Err(libc::EINVAL);
        }

        for (i, chunk) in self.buf.chunks_mut(8).enumerate() {
            let mut el = 0u64;
            loop {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut el) } == 1 {
                    chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                    break;
                } else {
                    if (self.flags & libc::GRND_NONBLOCK) != 0 {
                        return Err(libc::EAGAIN);
                    }
                    if (self.flags & libc::GRND_RANDOM) != 0 {
                        return Ok(i.checked_mul(8).unwrap());
                    }
                }
            }
        }
        Ok(self.buf.len())
    }
}

pub struct Getuid;

impl Stub for Getuid {
    type Ret = uid_t;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        FAKE_UID
    }
}

pub struct Readlink<'a> {
    pub pathname: &'a [u8],
    pub buf: &'a mut [u8],
}

impl Stub for Readlink<'_> {
    type Ret = Option<Result<size_t>>;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        if !self.pathname.eq("/proc/self/exe".as_bytes()) {
            return Some(Err(libc::ENOENT));
        }

        const DEST: &[u8; 6] = b"/init\0";
        if self.buf.len() < DEST.len() {
            return Some(Err(libc::EINVAL));
        }
        self.buf[..DEST.len()].copy_from_slice(DEST);
        Some(Ok(DEST.len()))
    }
}

pub struct RtSigprocmask<'a> {
    pub how: c_int,
    pub set: Option<&'a sigset_t>,
    pub oldset: Option<&'a mut sigset_t>,
    pub sigsetsize: size_t,
}

impl Stub for RtSigprocmask<'_> {
    type Ret = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        Ok(())
    }
}

pub struct Sigaltstack<'a> {
    pub ss: &'a stack_t,
    pub old_ss: Option<&'a mut stack_t>,
}

impl Stub for Sigaltstack<'_> {
    type Ret = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        Ok(())
    }
}

pub struct SetTidAddress<'a> {
    pub tidptr: &'a mut c_int,
}

impl Stub for SetTidAddress<'_> {
    type Ret = pid_t;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        FAKE_TID
    }
}

pub struct Uname<'a> {
    pub buf: &'a mut utsname,
}

impl Stub for Uname<'_> {
    type Ret = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Ret {
        fn fill(buf: &mut [c_char; 65], with: &str) {
            let src = with.as_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *src.get(i).unwrap_or(&0) as _;
            }
        }
        fill(&mut self.buf.sysname, "Linux");
        fill(&mut self.buf.nodename, "localhost.localdomain");
        fill(&mut self.buf.release, "5.6.0");
        fill(&mut self.buf.version, "#1");
        fill(&mut self.buf.machine, "x86_64");
        Ok(())
    }
}
