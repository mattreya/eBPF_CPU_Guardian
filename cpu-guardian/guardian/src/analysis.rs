use std::collections::HashMap;
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

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
        if event.event_type == EVENT_TYPE_FORK {
            let fork = unsafe { event.data.fork };
            let parent_is_bot = self.processes.get(&fork.parent_pid).map_or(false, |p| p.is_bot);

            let child_state = self.processes.entry(fork.child_pid).or_insert(ProcessState {
                pid: fork.child_pid,
                score: 0,
                comm: String::new(),
                is_bot: false,
            });

            if parent_is_bot {
                child_state.is_bot = true;
                return Some(fork.child_pid);
            }
            return None;
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
                if comm.contains("chromium") || comm.contains("firefox") || comm.contains("headless") ||
                   comm.contains("openclaw") || comm.contains("clawbot") || comm.contains("bot") {
                    state.score += 50;
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
        // Second call should return None as it's already a bot
        assert_eq!(analyzer.handle_event(event), None);
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // 1. Make PID 100 a bot
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 100,
            data: EventData {
                exec: ExecEvent {
                    pid: 100,
                    tgid: 100,
                    comm: [0; 16],
                },
            },
        };
        let comm = b"chromium\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }
        analyzer.handle_event(event);

        // 2. Fork child PID 200
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 100,
            data: EventData {
                fork: ForkEvent {
                    parent_pid: 100,
                    child_pid: 200,
                },
            },
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(200));

        // 3. Child PID 200 should now be marked as bot
        assert!(analyzer.processes.get(&200).unwrap().is_bot);
    }
}
