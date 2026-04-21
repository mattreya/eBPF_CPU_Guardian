use std::collections::HashMap;
use std::time::{Duration, Instant};
use guardian_common::{
    GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK,
    EVENT_TYPE_UNLINK, EVENT_TYPE_UNLINKAT,
    ExecEvent, ForkEvent, UnlinkEvent, EventData,
};

pub struct ProcessState {
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

    fn check_sensitive_extension(filename: &[u8]) -> bool {
        let name = std::str::from_utf8(filename)
            .unwrap_or("")
            .trim_matches(char::from(0));
        let lower = name.to_lowercase();
        lower.ends_with(".pdf") || lower.ends_with(".txt") || lower.ends_with(".doc")
    }

    pub fn handle_event(&mut self, event: GuardianEvent) -> Option<u32> {
        let mut newly_detected = false;

        match event.event_type {
            EVENT_TYPE_FORK => {
                let fork = unsafe { &event.data.fork };
                let is_bot = self.processes.get(&fork.parent_pid).map_or(false, |p| p.is_bot);

                self.processes.insert(fork.child_pid, ProcessState {
                    score: if is_bot { self.threshold } else { 0 },
                    comm: String::new(),
                    is_bot,
                    last_open_time: None,
                    open_count: 0,
                });

                if is_bot {
                    return Some(fork.child_pid);
                }
            }
            EVENT_TYPE_EXEC => {
                let state = self.processes.entry(event.pid).or_insert(ProcessState {
                    score: 0,
                    comm: String::new(),
                    is_bot: false,
                    last_open_time: None,
                    open_count: 0,
                });

                let exec = unsafe { &event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();

                let comm_lower = comm.to_lowercase();
                if ["chromium", "firefox", "openclaw", "clawbot", "moltbot", "headless", "bot"]
                    .iter()
                    .any(|&keyword| comm_lower.contains(keyword))
                {
                    state.score += 50;
                }

                if !state.is_bot && state.score >= self.threshold {
                    state.is_bot = true;
                    newly_detected = true;
                }
            }
            EVENT_TYPE_CONNECT => {
                let state = self.processes.entry(event.pid).or_insert(ProcessState {
                    score: 0,
                    comm: String::new(),
                    is_bot: false,
                    last_open_time: None,
                    open_count: 0,
                });

                state.score += 5;

                if !state.is_bot && state.score >= self.threshold {
                    state.is_bot = true;
                    newly_detected = true;
                }
            }
            EVENT_TYPE_OPEN => {
                let state = self.processes.entry(event.pid).or_insert(ProcessState {
                    score: 0,
                    comm: String::new(),
                    is_bot: false,
                    last_open_time: None,
                    open_count: 0,
                });

                let now = Instant::now();
                if let Some(last) = state.last_open_time {
                    if now.duration_since(last) < Duration::from_millis(100) {
                        state.open_count += 1;
                        if state.open_count > 10 {
                            state.score += 20;
                        }
                    } else {
                        state.open_count = 0;
                    }
                }
                state.last_open_time = Some(now);

                let open = unsafe { &event.data.open };
                if Self::check_sensitive_extension(&open.filename) {
                    state.score += 10;
                }

                if !state.is_bot && state.score >= self.threshold {
                    state.is_bot = true;
                    newly_detected = true;
                }
            }
            EVENT_TYPE_UNLINK | EVENT_TYPE_UNLINKAT => {
                let state = self.processes.entry(event.pid).or_insert(ProcessState {
                    score: 0,
                    comm: String::new(),
                    is_bot: false,
                    last_open_time: None,
                    open_count: 0,
                });

                state.score += 10;

                let filename = unsafe {
                    if event.event_type == EVENT_TYPE_UNLINK {
                        &event.data.unlink.filename
                    } else {
                        &event.data.unlinkat.filename
                    }
                };

                if Self::check_sensitive_extension(filename) {
                    state.score += 10;
                }

                if !state.is_bot && state.score >= self.threshold {
                    state.is_bot = true;
                    newly_detected = true;
                }
            }
            _ => {}
        }

        if newly_detected {
            Some(event.pid)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // Identify parent as bot
        let mut exec_event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 100,
            data: EventData {
                exec: ExecEvent { pid: 100, tgid: 100, comm: [0; 16] }
            }
        };
        let comm = b"openclaw\0";
        unsafe { exec_event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(exec_event);

        // Fork event
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 100,
            data: EventData {
                fork: ForkEvent { parent_pid: 100, child_pid: 101 }
            }
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(101));
    }

    #[test]
    fn test_unlink_scoring() {
        let mut analyzer = Analyzer::new(20);
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_UNLINK,
            pid: 1234,
            data: EventData {
                unlink: UnlinkEvent {
                    pid: 1234,
                    filename: [0; 64],
                }
            }
        };

        let filename = b"malicious.txt\0";
        unsafe {
            event.data.unlink.filename[..filename.len()].copy_from_slice(filename);
        }

        // 10 base + 10 for .txt = 20 (reaches threshold)
        assert_eq!(analyzer.handle_event(event), Some(1234));
    }
}
