#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::{tracepoint, map},
    maps::PerfEventArray,
    programs::TracePointContext,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
};
use guardian_common::{
    GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK,
    EVENT_TYPE_UNLINK, EVENT_TYPE_UNLINKAT,
    ExecEvent, ConnectEvent, OpenEvent, ForkEvent, UnlinkEvent, EventData
};

use core::mem;

#[map]
static mut EVENTS: PerfEventArray<GuardianEvent> = PerfEventArray::new(0);

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let filename_ptr: *const u8 = unsafe { ctx.read_at(16)? };

    let mut event = GuardianEvent {
        event_type: EVENT_TYPE_EXEC,
        pid,
        data: EventData {
            exec: ExecEvent {
                pid: tid,
                tgid: pid,
                comm: [0; 16],
            },
        },
    };

    unsafe {
        bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut event.data.exec.comm,
        )?;
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_unlink")]
pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sys_enter_unlink(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let filename_ptr: *const u8 = unsafe { ctx.read_at(16)? };

    let mut event = GuardianEvent {
        event_type: EVENT_TYPE_UNLINK,
        pid,
        data: EventData {
            unlink: UnlinkEvent {
                pid,
                filename: [0; 64],
            },
        },
    };

    unsafe {
        bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut event.data.unlink.filename,
        )?;
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_unlinkat")]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sys_enter_unlinkat(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    let mut event = GuardianEvent {
        event_type: EVENT_TYPE_UNLINKAT,
        pid,
        data: EventData {
            unlink: UnlinkEvent {
                pid,
                filename: [0; 64],
            },
        },
    };

    unsafe {
        bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut event.data.unlink.filename,
        )?;
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let addr_ptr: *const sockaddr = unsafe { ctx.read_at(24)? };

    let sa: sockaddr = unsafe { bpf_probe_read_user(addr_ptr)? };

    if sa.sa_family == 2 { // AF_INET
        let sin: sockaddr_in = unsafe { mem::transmute(sa) };
        let event = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            data: EventData {
                connect: ConnectEvent {
                    pid,
                    addr: sin.sin_addr.s_addr,
                    port: sin.sin_port.to_be(),
                },
            },
        };
        unsafe {
            EVENTS.output(&ctx, &event, 0);
        }
    }

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    let mut event = GuardianEvent {
        event_type: EVENT_TYPE_OPEN,
        pid,
        data: EventData {
            open: OpenEvent {
                pid,
                filename: [0; 64],
            },
        },
    };

    unsafe {
        bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut event.data.open.filename,
        )?;
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, i64> {
    let parent_pid: u32 = unsafe { ctx.read_at(24)? };
    let child_pid: u32 = unsafe { ctx.read_at(44)? };

    let event = GuardianEvent {
        event_type: EVENT_TYPE_FORK,
        pid: parent_pid,
        data: EventData {
            fork: ForkEvent {
                parent_pid,
                child_pid,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[repr(C)]
#[derive(Copy, Clone)]
struct sockaddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: in_addr,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct in_addr {
    s_addr: u32,
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
