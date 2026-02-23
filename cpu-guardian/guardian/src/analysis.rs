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
            let parent_is_bot = self.processes.get(&fork.parent_pid).map(|s| s.is_bot).unwrap_or(false);

            if parent_is_bot {
                self.processes.insert(fork.child_pid, ProcessState {
                    pid: fork.child_pid,
                    score: 100, // At least the threshold
                    comm: String::from("inherited-bot"),
                    is_bot: true,
                });
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

                // Bot identification keywords from README/SUMMARY
                if comm.contains("openclaw") || comm.contains("clawbot") || comm.contains("headless") || comm.contains("bot") {
                    state.score += 100;
                } else if comm.contains("chromium") || comm.contains("firefox") {
                    state.score += 50;
                }
            }
            EVENT_TYPE_CONNECT => {
                // High-volume network requests could be tracked here, but for now just increment
                state.score += 10;
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));

                // Rapid sequential access to document files
                if filename.ends_with(".pdf") || filename.ends_with(".doc") || filename.ends_with(".txt") {
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
        let mut analyzer = Analyzer::new(100);
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

        // Redundant call should return None
        assert_eq!(analyzer.handle_event(event), None);
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(100);

        // 1. Identify parent as bot
        let mut exec_event = GuardianEvent {
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
        let comm = b"openclaw\0";
        unsafe {
            exec_event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }
        analyzer.handle_event(exec_event);

        // 2. Parent forks
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 100,
            data: EventData {
                fork: ForkEvent {
                    parent_pid: 100,
                    child_pid: 101,
                },
            },
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(101));
    }

    #[test]
    fn test_behavioral_scoring() {
        let mut analyzer = Analyzer::new(50);

        // Open 3 pdf files
        for i in 0..3 {
            let mut event = GuardianEvent {
                event_type: EVENT_TYPE_OPEN,
                pid: 200,
                data: EventData {
                    open: OpenEvent {
                        pid: 200,
                        filename: [0; 64],
                    },
                },
            };
            let filename = b"document.pdf\0";
            unsafe {
                event.data.open.filename[..filename.len()].copy_from_slice(filename);
            }
            let res = analyzer.handle_event(event);
            if i < 2 {
                assert_eq!(res, None);
            } else {
                assert_eq!(res, Some(200));
            }
        }
    }
}
