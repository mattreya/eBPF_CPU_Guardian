#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::{tracepoint, map},
    maps::PerfEventArray,
    programs::TracePointContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK, ExecEvent, ConnectEvent, OpenEvent, ForkEvent, EventData};

use core::mem;

#[map]
static mut EVENTS: PerfEventArray<GuardianEvent> = PerfEventArray::with_max_entries(1024, 0);

#[tracepoint(category = "syscalls", name = "guardian_exec")]
pub fn guardian_exec(ctx: TracePointContext) -> u32 {
    match try_guardian_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_guardian_exec(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let event = GuardianEvent {
        event_type: EVENT_TYPE_EXEC,
        pid,
        data: EventData {
            exec: ExecEvent {
                pid: tid,
                tgid: pid,
                comm: bpf_get_current_comm()?,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "guardian_connect")]
pub fn guardian_connect(ctx: TracePointContext) -> u32 {
    match try_guardian_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_guardian_connect(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let addr_ptr: *const sockaddr = unsafe { ctx.read_at(24)? };

    let mut sa = sockaddr { sa_family: 0, sa_data: [0; 14] };
    unsafe {
        bpf_probe_read_user(&mut sa, mem::size_of::<sockaddr>() as u32, addr_ptr as *const _)?;
    }

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

#[tracepoint(category = "syscalls", name = "guardian_openat")]
pub fn guardian_openat(ctx: TracePointContext) -> u32 {
    match try_guardian_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_guardian_openat(ctx: TracePointContext) -> Result<u32, i64> {
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
            &mut event.data.open.filename
        )?;
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[tracepoint(category = "sched", name = "guardian_fork")]
pub fn guardian_fork(ctx: TracePointContext) -> u32 {
    match try_guardian_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_guardian_fork(ctx: TracePointContext) -> Result<u32, i64> {
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
struct sockaddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: in_addr,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct in_addr {
    s_addr: u32,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
