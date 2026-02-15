use std::collections::{HashMap, HashSet};
use std::time::{Instant, Duration};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct ProcessEvent {
    pub timestamp: Instant,
    pub points: u32,
}

pub struct ProcessState {
    pub comm: String,
    pub events: Vec<ProcessEvent>,
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
        let now = Instant::now();
        let window = Duration::from_secs(10);

        if event.event_type == EVENT_TYPE_FORK {
            let fork = unsafe { event.data.fork };
            if self.bots.contains(&fork.parent_pid) {
                self.bots.insert(fork.child_pid);
                return Some(fork.child_pid);
            }
            return None;
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            comm: String::new(),
            events: Vec::new(),
        });

        // Clean up old events
        state.events.retain(|e| now.duration_since(e.timestamp) < window);

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();

                let mut points = 0;
                if comm.contains("chromium") || comm.contains("firefox") || comm.contains("headless") || comm.contains("openclaw") {
                    points = 50;
                }
                if points > 0 {
                    state.events.push(ProcessEvent { timestamp: now, points });
                }
            }
            EVENT_TYPE_CONNECT => {
                state.events.push(ProcessEvent { timestamp: now, points: 10 });
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".txt") || filename.ends_with(".doc") {
                    state.events.push(ProcessEvent { timestamp: now, points: 20 });
                }
            }
            _ => {}
        }

        let total_score: u32 = state.events.iter().map(|e| e.points).sum();

        if total_score >= self.threshold {
            if self.bots.insert(event.pid) {
                return Some(event.pid);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_common::*;

    #[test]
    fn test_scoring_window() {
        let mut analyzer = Analyzer::new(50);
        let pid = 1234;

        let event = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            data: EventData {
                connect: ConnectEvent { pid, addr: 0, port: 80 },
            },
        };

        // 4 connects = 40 points (less than 50)
        for _ in 0..4 {
            assert_eq!(analyzer.handle_event(event), None);
        }

        // 5th connect = 50 points -> detected
        assert_eq!(analyzer.handle_event(event), Some(pid));
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);
        let parent_pid = 1234;
        let child_pid = 5678;

        // Flag parent
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: parent_pid,
            data: EventData {
                exec: ExecEvent { pid: parent_pid, tgid: parent_pid, comm: [0; 16] },
            },
        };
        let comm = b"openclaw\0";
        unsafe { event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(event);

        // Fork
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: parent_pid,
            data: EventData {
                fork: ForkEvent { parent_pid, child_pid },
            },
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(child_pid));
    }
}
