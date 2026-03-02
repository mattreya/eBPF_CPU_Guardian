use std::collections::HashMap;
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
    pub is_bot: bool,
    pub last_open_time: Option<std::time::Instant>,
    pub open_count: u32,
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

            self.processes.insert(fork.child_pid, ProcessState {
                pid: fork.child_pid,
                score: if parent_is_bot { self.threshold } else { 0 },
                comm: self.processes.get(&fork.parent_pid).map_or(String::new(), |p| p.comm.clone()),
                is_bot: parent_is_bot,
                last_open_time: None,
                open_count: 0,
            });

            return if parent_is_bot { Some(fork.child_pid) } else { None };
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            score: 0,
            comm: String::new(),
            is_bot: false,
            last_open_time: None,
            open_count: 0,
        });

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();
                if comm.contains("chromium") || comm.contains("firefox") || comm.contains("headless") {
                    state.score += 50;
                }
            }
            EVENT_TYPE_CONNECT => {
                state.score += 5;
            }
            EVENT_TYPE_OPEN => {
                let now = std::time::Instant::now();
                if let Some(last) = state.last_open_time {
                    if now.duration_since(last).as_secs() < 1 {
                        state.open_count += 1;
                        if state.open_count > 10 {
                            state.score += 20;
                            // Reset counter to avoid double-penalizing within the same second
                            state.open_count = 0;
                        }
                    } else {
                        state.open_count = 1;
                        state.last_open_time = Some(now);
                    }
                } else {
                    state.open_count = 1;
                    state.last_open_time = Some(now);
                }

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
    }

    #[test]
    fn test_fork_inheritance() {
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
        let comm = b"chromium\0";
        unsafe { exec_event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(exec_event);

        // 2. Fork
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

        // Child should be immediately detected as bot
        assert_eq!(analyzer.handle_event(fork_event), Some(1001));
        assert!(analyzer.processes.get(&1001).unwrap().is_bot);
    }

    #[test]
    fn test_rapid_open() {
        let mut analyzer = Analyzer::new(20);
        let pid = 2000;

        for _ in 0..11 {
            let event = GuardianEvent {
                event_type: EVENT_TYPE_OPEN,
                pid,
                data: EventData {
                    open: OpenEvent {
                        pid,
                        filename: [0; 64],
                    },
                },
            };
            analyzer.handle_event(event);
        }

        assert!(analyzer.processes.get(&pid).unwrap().score >= 20);
        assert_eq!(analyzer.processes.get(&pid).unwrap().is_bot, true);
    }
}
