use std::collections::HashMap;
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};
use log::debug;

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
    pub is_bot: bool,
}

pub struct Analyzer {
    processes: HashMap<u32, ProcessState>,
    threshold: u32,
}

impl Analyzer {
    pub fn new(threshold: u32) -> Self {
        Self {
            processes: HashMap::new(),
            threshold,
        }
    }

    pub fn handle_event(&mut self, event: GuardianEvent) -> Option<u32> {
        match event.event_type {
            EVENT_TYPE_FORK => {
                let fork = unsafe { event.data.fork };
                let parent_is_bot = self.processes.get(&fork.parent_pid).map_or(false, |p| p.is_bot);

                let child_state = self.processes.entry(fork.child_pid).or_insert(ProcessState {
                    pid: fork.child_pid,
                    score: 0,
                    comm: String::new(),
                    is_bot: false,
                });

                if parent_is_bot && !child_state.is_bot {
                    child_state.is_bot = true;
                    child_state.score = self.threshold; // Inherit bot status
                    debug!("Process {} inherited bot status from parent {}", fork.child_pid, fork.parent_pid);
                    return Some(fork.child_pid);
                }
                return None;
            }
            _ => {}
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            score: 0,
            comm: String::new(),
            is_bot: false,
        });

        if state.is_bot {
            return None; // Already flagged and handled
        }

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_lowercase();

                let bot_keywords = ["openclaw", "clawbot", "headless", "bot"];
                for keyword in bot_keywords {
                    if state.comm.contains(keyword) {
                        state.score += 50;
                        break;
                    }
                }
            }
            EVENT_TYPE_CONNECT => {
                state.score += 10;
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0))
                    .to_lowercase();

                if filename.ends_with(".pdf") || filename.ends_with(".doc") {
                    state.score += 20;
                }
            }
            _ => {}
        }

        if state.score >= self.threshold {
            state.is_bot = true;
            Some(state.pid)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_common::*;

    #[test]
    fn test_scoring() {
        let mut analyzer = Analyzer::new(50);
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 1234,
            data: EventData {
                exec: ExecEvent {
                    pid: 1234,
                    tgid: 1234,
                    comm: [0; 16],
                },
            },
        };

        // Mock a bot process
        let comm = b"openclaw\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }

        assert_eq!(analyzer.handle_event(event), Some(1234));
        // Second call should return None
        assert_eq!(analyzer.handle_event(event), None);
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // 1. Flag PID 100 as bot
        let mut exec_event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 100,
            data: EventData {
                exec: ExecEvent { pid: 100, tgid: 100, comm: [0; 16] },
            },
        };
        let comm = b"openclaw\0";
        unsafe { exec_event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(exec_event);

        // 2. Fork PID 100 -> 101
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 100,
            data: EventData {
                fork: ForkEvent { parent_pid: 100, child_pid: 101 },
            },
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(101));

        // 3. Subsequent event from 101 should return None (already flagged)
        let connect_event = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid: 101,
            data: EventData {
                connect: ConnectEvent { pid: 101, addr: 0, port: 80 },
            },
        };
        assert_eq!(analyzer.handle_event(connect_event), None);
    }
}
