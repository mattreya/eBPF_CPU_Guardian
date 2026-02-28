use std::collections::{HashMap, HashSet};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
    pub is_bot: bool,
}

pub struct Analyzer {
    processes: HashMap<u32, ProcessState>,
    bots: HashSet<u32>,
    threshold: u32,
}

impl Analyzer {
    pub fn new(threshold: u32) -> Self {
        Self {
            processes: HashMap::new(),
            bots: HashSet::new(),
            threshold,
        }
    }

    pub fn handle_event(&mut self, event: GuardianEvent) -> Option<u32> {
        match event.event_type {
            EVENT_TYPE_FORK => {
                let fork = unsafe { event.data.fork };
                if self.bots.contains(&fork.parent_pid) {
                    self.bots.insert(fork.child_pid);
                    self.processes.insert(fork.child_pid, ProcessState {
                        pid: fork.child_pid,
                        score: self.threshold,
                        comm: "inherited-bot".to_string(),
                        is_bot: true,
                    });
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
            return None;
        }

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();

                let bot_keywords = ["chromium", "firefox", "openclaw", "clawbot", "moltbot", "headless", "bot"];
                for keyword in bot_keywords {
                    if comm.contains(keyword) {
                        state.score += 50;
                        break;
                    }
                }
            }
            EVENT_TYPE_CONNECT => {
                state.score += 5;
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".txt") || filename.ends_with(".doc") {
                    state.score += 10;
                }
            }
            _ => {}
        }

        if state.score >= self.threshold {
            state.is_bot = true;
            self.bots.insert(state.pid);
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

        // Mock a chromium process
        let comm = b"chromium\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }

        assert_eq!(analyzer.handle_event(event), Some(1234));
        // Redundant event should not return PID again
        assert_eq!(analyzer.handle_event(event), None);
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // 1. Identify parent as bot
        let mut exec_event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 1000,
            data: EventData {
                exec: ExecEvent {
                    pid: 1000,
                    tgid: 1000,
                    comm: [0; 16],
                },
            },
        };
        let comm = b"clawbot\0";
        unsafe { exec_event.data.exec.comm[..comm.len()].copy_from_slice(comm); }

        assert_eq!(analyzer.handle_event(exec_event), Some(1000));

        // 2. Parent forks a child
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 1000,
            data: EventData {
                fork: ForkEvent {
                    parent_pid: 1000,
                    child_pid: 1001,
                },
            },
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(1001));

        // 3. Child is already marked as bot
        let child_connect = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid: 1001,
            data: EventData {
                connect: ConnectEvent {
                    pid: 1001,
                    addr: 0,
                    port: 80,
                },
            },
        };
        assert_eq!(analyzer.handle_event(child_connect), None);
    }
}
