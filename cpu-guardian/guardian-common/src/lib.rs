#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExecEvent {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 64],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectEvent {
    pub pid: u32,
    pub addr: u32, // IPv4 address
    pub port: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct OpenEvent {
    pub pid: u32,
    pub filename: [u8; 64],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ForkEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
}

pub const EVENT_TYPE_EXEC: u32 = 1;
pub const EVENT_TYPE_CONNECT: u32 = 2;
pub const EVENT_TYPE_OPEN: u32 = 3;
pub const EVENT_TYPE_FORK: u32 = 4;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GuardianEvent {
    pub event_type: u32,
    pub pid: u32,
    pub data: EventData,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union EventData {
    pub exec: ExecEvent,
    pub connect: ConnectEvent,
    pub open: OpenEvent,
    pub fork: ForkEvent,
}
