use std::collections::HashMap;
use std::time::{Duration, Instant};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
    pub net_events: Vec<Instant>,
    pub file_events: Vec<Instant>,
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
        let now = Instant::now();

        if event.event_type == EVENT_TYPE_FORK {
            let fork = unsafe { event.data.fork };
            let is_parent_bot = self.processes.get(&fork.parent_pid).map(|s| s.is_bot).unwrap_or(false);

            if is_parent_bot {
                self.processes.insert(fork.child_pid, ProcessState {
                    pid: fork.child_pid,
                    score: 1000,
                    comm: String::new(),
                    net_events: Vec::new(),
                    file_events: Vec::new(),
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
            net_events: Vec::new(),
            file_events: Vec::new(),
            is_bot: false,
        });

        if state.is_bot {
            return None; // Already detected and reported
        }

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();
                if comm.contains("chromium") || comm.contains("firefox") || comm.contains("headless") {
                    state.score += 40;
                }
                if comm.contains("moltbot") || comm.contains("clawbot") || comm.contains("openclaw") {
                    state.score += 100;
                }
            }
            EVENT_TYPE_CONNECT => {
                state.net_events.push(now);
                state.net_events.retain(|&t| now.duration_since(t) < Duration::from_secs(10));
                if state.net_events.len() > 10 {
                    state.score += 20;
                    state.net_events.clear();
                }
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".txt") || filename.ends_with(".doc") || filename.ends_with(".docx") {
                    state.file_events.push(now);
                    state.file_events.retain(|&t| now.duration_since(t) < Duration::from_secs(10));
                    if state.file_events.len() > 3 {
                        state.score += 30;
                        state.file_events.clear();
                    }
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

        assert_eq!(analyzer.handle_event(event), None); // Only 40 points

        // Add some network events
        let mut detected_pid = None;
        for _ in 0..11 {
            let net_event = GuardianEvent {
                event_type: EVENT_TYPE_CONNECT,
                pid: 1234,
                data: EventData {
                    connect: ConnectEvent {
                        pid: 1234,
                        addr: 0,
                        port: 0,
                    },
                },
            };
            if let Some(pid) = analyzer.handle_event(net_event) {
                detected_pid = Some(pid);
            }
        }

        // Now score should be 40 + 20 = 60, which is > 50
        assert_eq!(detected_pid, Some(1234));
    }
}
