// SPDX-License-Identifier: Apache-2.0

use super::Execute;
use crate::{item, Result};

use core::arch::asm;
use core::mem::size_of;
use libc::{c_long, timespec};

struct Syscall<'a, const ARGS: usize, const RETS: usize> {
    /// The syscall number for the request.
    ///
    /// See, for example, [`libc::SYS_exit`](libc::SYS_exit).
    num: c_long,

    /// The syscall argument vector.
    argv: [usize; ARGS],

    /// Return values.
    ret: [&'a mut usize; RETS],
}

impl Execute for Syscall<'_, 0, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 1, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 2, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 3, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 4, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 5, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        in("r8") self.argv[4],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 6, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        in("r8") self.argv[4],
        in("r9") self.argv[5],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

/// Validates that `data` contains `len` elements of type `T` at `offset`
/// and returns a mutable pointer to the first element on success.
/// NOTE: callers must ensure that pointer is correctly aligned before accessing it.
fn deref<T>(data: &mut [u8], offset: usize, len: usize) -> Result<*mut T> {
    let size = len * size_of::<T>();
    if size > data.len() || data.len() - size < offset {
        Err(libc::EFAULT)
    } else {
        Ok(data[offset..offset + size].as_mut_ptr() as _)
    }
}

pub(super) unsafe fn execute_syscall(syscall: &mut item::Syscall, data: &mut [u8]) -> Result<()> {
    match syscall {
        item::Syscall {
            num,
            argv: [sockfd, addr_offset, addrlen, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_bind as _ => {
            let addr = deref::<u8>(data, *addr_offset, *addrlen)?;
            Syscall {
                num: libc::SYS_bind,
                argv: [*sockfd, addr as _, *addrlen],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [clockid, tp_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_clock_gettime as _ => {
            let tp = deref::<timespec>(data, *tp_offset, 1)?;
            Syscall {
                num: libc::SYS_clock_gettime,
                argv: [*clockid, tp as _],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [fd, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_close as _ => Syscall {
            num: libc::SYS_close,
            argv: [*fd],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [sockfd, addr_offset, addrlen, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_connect as _ => {
            let addr = deref::<u8>(data, *addr_offset, *addrlen)?;
            Syscall {
                num: libc::SYS_connect,
                argv: [*sockfd, addr as _, *addrlen],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [oldfd, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_dup as _ => Syscall {
            num: libc::SYS_dup,
            argv: [*oldfd],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [oldfd, newfd, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_dup2 as _ => Syscall {
            num: libc::SYS_dup2,
            argv: [*oldfd, *newfd],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [oldfd, newfd, flags, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_dup3 as _ => Syscall {
            num: libc::SYS_dup3,
            argv: [*oldfd, *newfd, *flags],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [initval, flags, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_eventfd2 as _ => Syscall {
            num: libc::SYS_eventfd2,
            argv: [*initval, *flags],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [status, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_exit as _ => Syscall {
            num: libc::SYS_exit,
            argv: [*status],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [status, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_exit_group as _ => Syscall {
            num: libc::SYS_exit_group,
            argv: [*status],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [fd, cmd, arg, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_fcntl as _ => Syscall {
            num: libc::SYS_fcntl,
            argv: [*fd, *cmd, *arg],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [sockfd, backlog, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_listen as _ => Syscall {
            num: libc::SYS_listen,
            argv: [*sockfd, *backlog],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [fd, buf_offset, count, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_read as _ => {
            let buf = deref::<u8>(data, *buf_offset, *count)?;
            Syscall {
                num: libc::SYS_read,
                argv: [*fd, buf as _, *count],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [sockfd, level, optname, optval_offset, optlen, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_setsockopt as _ => {
            let optval = deref::<u8>(data, *optval_offset, *optlen)?;
            Syscall {
                num: libc::SYS_setsockopt,
                argv: [*sockfd, *level, *optname, optval as _, *optlen],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [domain, typ, protocol, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_socket as _ => Syscall {
            num: libc::SYS_socket,
            argv: [*domain, *typ, *protocol],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: _,
            ret: [ret, ..],
        } if *num == libc::SYS_sync as _ => Syscall {
            num: libc::SYS_sync,
            argv: [],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [fd, buf_offset, count, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_write as _ => {
            let buf = deref::<u8>(data, *buf_offset, *count)?;
            Syscall {
                num: libc::SYS_write,
                argv: [*fd, buf as _, *count],
                ret: [ret],
            }
            .execute();
        }

        _ => return Err(libc::ENOSYS),
    }
    Ok(())
}
