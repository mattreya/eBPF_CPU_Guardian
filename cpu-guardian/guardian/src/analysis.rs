use std::collections::HashMap;
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};
use log::info;

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
                let parent_is_bot = self.processes.get(&fork.parent_pid).map(|p| p.is_bot).unwrap_or(false);

                let child_state = ProcessState {
                    pid: fork.child_pid,
                    score: if parent_is_bot { self.threshold } else { 0 },
                    comm: self.processes.get(&fork.parent_pid).map(|p| p.comm.clone()).unwrap_or_default(),
                    is_bot: parent_is_bot,
                };
                self.processes.insert(fork.child_pid, child_state);

                if parent_is_bot {
                    info!("Child process {} inherited bot status from parent {}", fork.child_pid, fork.parent_pid);
                    return Some(fork.child_pid);
                }
                None
            }
            _ => {
                let state = self.processes.entry(event.pid).or_insert(ProcessState {
                    pid: event.pid,
                    score: 0,
                    comm: String::new(),
                    is_bot: false,
                });

                if state.is_bot {
                    return None; // Already flagged
                }

                match event.event_type {
                    EVENT_TYPE_EXEC => {
                        let exec = unsafe { event.data.exec };
                        let comm = std::str::from_utf8(&exec.comm)
                            .unwrap_or("")
                            .trim_matches(char::from(0));
                        state.comm = comm.to_string();
                        let comm_lower = comm.to_lowercase();
                        if comm_lower.contains("openclaw") || comm_lower.contains("clawbot") || comm_lower.contains("headless") || comm_lower.contains("bot") {
                            state.score += 50;
                        }
                    }
                    EVENT_TYPE_CONNECT => {
                        state.score += 10;
                    }
                    EVENT_TYPE_OPEN => {
                        let open = unsafe { event.data.open };
                        let filename = std::str::from_utf8(&open.filename)
                            .unwrap_or("")
                            .trim_matches(char::from(0));
                        if filename.ends_with(".pdf") || filename.ends_with(".doc") || filename.ends_with(".docx") {
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

        // Mock an openclaw process
        let comm = b"openclaw\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }

        assert_eq!(analyzer.handle_event(event), Some(1234));
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // 1. Flag parent as bot
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
        let comm = b"openclaw\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }
        analyzer.handle_event(event);

        // 2. Fork
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 1234,
            data: EventData {
                fork: ForkEvent {
                    parent_pid: 1234,
                    child_pid: 5678,
                },
            },
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(5678));
        assert!(analyzer.processes.get(&5678).unwrap().is_bot);
    }
}
