// SPDX-License-Identifier: Apache-2.0

use super::Execute;
use crate::{item, Result};

use core::arch::asm;
use libc::c_long;

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

pub(super) unsafe fn execute_syscall(syscall: &mut item::Syscall, _data: &mut [u8]) -> Result<()> {
    match syscall {
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
        _ => return Err(libc::ENOSYS),
    }
    Ok(())
}
