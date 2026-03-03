use std::collections::HashMap;
use std::time::{Instant, Duration};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
    pub is_bot: bool,
    pub last_open_time: Option<Instant>,
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
                comm: String::new(),
                is_bot: parent_is_bot,
                last_open_time: None,
                open_count: 0,
            });

            if parent_is_bot {
                return Some(fork.child_pid);
            }
            return None;
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            score: 0,
            comm: String::new(),
            is_bot: false,
            last_open_time: None,
            open_count: 0,
        });

        // If it's already a bot, we don't need to re-detect it unless it's a new fork (handled above)
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

                // Rapid file access detection
                let now = Instant::now();
                if let Some(last_open) = state.last_open_time {
                    if now.duration_since(last_open) < Duration::from_millis(100) {
                        state.open_count += 1;
                        if state.open_count > 10 {
                            state.score += 20;
                            state.open_count = 0; // Reset after penalty
                        }
                    } else {
                        state.open_count = 0;
                    }
                }
                state.last_open_time = Some(now);
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
        let comm = b"moltbot\0";
        unsafe { exec_event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(exec_event);

        // 2. Fork event
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
        assert!(analyzer.processes.get(&1001).unwrap().is_bot);
    }
}
