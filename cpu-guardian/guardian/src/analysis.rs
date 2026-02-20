use std::collections::{HashMap, HashSet};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};
use log::{debug, info};

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
    pub is_bot: bool,
}

pub struct Analyzer {
    processes: HashMap<u32, ProcessState>,
    threshold: u32,
    bots: HashSet<u32>,
}

impl Analyzer {
    pub fn new(threshold: u32) -> Self {
        Self {
            processes: HashMap::new(),
            threshold,
            bots: HashSet::new(),
        }
    }

    pub fn handle_event(&mut self, event: GuardianEvent) -> Option<u32> {
        match event.event_type {
            EVENT_TYPE_FORK => {
                let fork = unsafe { event.data.fork };
                debug!("Fork event: parent {} -> child {}", fork.parent_pid, fork.child_pid);
                if self.bots.contains(&fork.parent_pid) {
                    info!("Propagating bot status from {} to {}", fork.parent_pid, fork.child_pid);
                    let parent_comm = self.processes.get(&fork.parent_pid).map(|p| p.comm.clone()).unwrap_or_default();
                    self.bots.insert(fork.child_pid);
                    let state = self.processes.entry(fork.child_pid).or_insert(ProcessState {
                        pid: fork.child_pid,
                        score: self.threshold,
                        comm: parent_comm,
                        is_bot: true,
                    });
                    state.is_bot = true;
                    state.score = self.threshold;
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
                if comm.contains("headless") || comm.contains("openclaw") || comm.contains("clawbot") || comm.contains("moltbot") {
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
                if filename.ends_with(".pdf") || filename.ends_with(".doc") || filename.ends_with(".docx") || filename.ends_with(".txt") {
                    state.score += 20;
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

        let comm = b"openclaw\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }

        assert_eq!(analyzer.handle_event(event), Some(1234));
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // Make 1234 a bot
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
        unsafe { event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(event);

        // Fork 1234 -> 5678
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
    }
}
