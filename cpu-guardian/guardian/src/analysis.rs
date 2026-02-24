use std::collections::{HashMap, HashSet};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};
use log::debug;

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
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
                    debug!("Inheriting bot status from {} to {}", fork.parent_pid, fork.child_pid);
                    self.bots.insert(fork.child_pid);
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
        });

        if self.bots.contains(&event.pid) {
            return None;
        }

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                let filename = std::str::from_utf8(&exec.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));

                state.comm = comm.to_string();

                let keywords = ["chromium", "firefox", "headless", "bot", "openclaw", "clawbot"];
                for &kw in keywords.iter() {
                    if comm.contains(kw) || filename.contains(kw) {
                        state.score += 50;
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
                    filename: [0; 64],
                },
            },
        };

        // Mock a chromium process
        let comm = b"chromium\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }

        assert_eq!(analyzer.handle_event(event), Some(1234));
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // Mark 1234 as bot
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 1234,
            data: EventData {
                exec: ExecEvent {
                    pid: 1234,
                    tgid: 1234,
                    comm: [0; 16],
                    filename: [0; 64],
                },
            },
        };
        let comm = b"clawbot\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }
        analyzer.handle_event(event);
        assert!(analyzer.bots.contains(&1234));

        // Fork event
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
        assert!(analyzer.bots.contains(&5678));
    }
}
