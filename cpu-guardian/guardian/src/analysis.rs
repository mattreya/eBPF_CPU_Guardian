use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct EventRecord {
    pub timestamp: Instant,
    pub event_type: u32,
}

pub struct ProcessState {
    pub pid: u32,
    pub comm: String,
    pub events: Vec<EventRecord>,
    pub is_bot: bool,
}

pub struct Analyzer {
    processes: HashMap<u32, ProcessState>,
    bot_pids: HashSet<u32>,
    threshold: u32,
}

impl Analyzer {
    pub fn new(threshold: u32) -> Self {
        Self {
            processes: HashMap::new(),
            bot_pids: HashSet::new(),
            threshold,
        }
    }

    pub fn handle_event(&mut self, event: GuardianEvent) -> Option<u32> {
        let now = Instant::now();
        let window = Duration::from_secs(10);

        if event.event_type == EVENT_TYPE_FORK {
            let fork = unsafe { event.data.fork };
            if self.bot_pids.contains(&fork.parent_pid) {
                self.bot_pids.insert(fork.child_pid);
                return Some(fork.child_pid);
            }
            return None;
        }

        let state = self.processes.entry(event.pid).or_insert_with(|| ProcessState {
            pid: event.pid,
            comm: String::new(),
            events: Vec::new(),
            is_bot: self.bot_pids.contains(&event.pid),
        });

        if state.is_bot {
            return Some(event.pid);
        }

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();
                if comm.contains("headless") || comm.contains("openclaw") {
                    state.is_bot = true;
                }
            }
            EVENT_TYPE_CONNECT => {
                state.events.push(EventRecord {
                    timestamp: now,
                    event_type: EVENT_TYPE_CONNECT,
                });
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".doc") {
                    state.events.push(EventRecord {
                        timestamp: now,
                        event_type: EVENT_TYPE_OPEN,
                    });
                }
            }
            _ => {}
        }

        // Clean up old events
        state.events.retain(|e| now.duration_since(e.timestamp) < window);

        // Calculate score
        let mut score = 0;
        if state.is_bot {
            score = self.threshold;
        } else {
            for e in &state.events {
                match e.event_type {
                    EVENT_TYPE_CONNECT => score += 10,
                    EVENT_TYPE_OPEN => score += 20,
                    _ => {}
                }
            }
        }

        if score >= self.threshold {
            state.is_bot = true;
            self.bot_pids.insert(event.pid);
            Some(event.pid)
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

        // 5 connect events = 50 points
        for _ in 0..4 {
            let event = GuardianEvent {
                event_type: EVENT_TYPE_CONNECT,
                pid: 1234,
                data: EventData { connect: ConnectEvent { pid: 1234, addr: 0, port: 0 } },
            };
            analyzer.handle_event(event);
        }

        // Should be detected on the 5th event
        let last_event = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid: 1234,
            data: EventData { connect: ConnectEvent { pid: 1234, addr: 0, port: 0 } },
        };
        assert_eq!(analyzer.handle_event(last_event), Some(1234));
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // Mark 1234 as bot via name
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 1234,
            data: EventData { exec: ExecEvent { pid: 1234, tgid: 1234, comm: [0; 16] } },
        };
        let comm = b"openclaw\0";
        unsafe { event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(event);

        // Fork
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 1234,
            data: EventData { fork: ForkEvent { parent_pid: 1234, child_pid: 5678 } },
        };
        assert_eq!(analyzer.handle_event(fork_event), Some(5678));
    }
}
