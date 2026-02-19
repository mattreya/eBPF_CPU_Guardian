use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct EventRecord {
    pub timestamp: Instant,
    pub points: u32,
}

pub struct ProcessState {
    pub pid: u32,
    pub comm: String,
    pub events: VecDeque<EventRecord>,
    pub is_bot: bool,
}

pub struct Analyzer {
    processes: HashMap<u32, ProcessState>,
    threshold: u32,
    window_duration: Duration,
}

impl Analyzer {
    pub fn new(threshold: u32) -> Self {
        Self {
            processes: HashMap::new(),
            threshold,
            window_duration: Duration::from_secs(10),
        }
    }

    fn calculate_score(state: &ProcessState, window_duration: Duration) -> u32 {
        let now = Instant::now();
        state.events.iter()
            .filter(|e| now.duration_since(e.timestamp) <= window_duration)
            .map(|e| e.points)
            .sum()
    }

    pub fn handle_event(&mut self, event: GuardianEvent) -> Option<u32> {
        let now = Instant::now();

        if event.event_type == EVENT_TYPE_FORK {
            let fork = unsafe { event.data.fork };
            let parent_is_bot = self.processes.get(&fork.parent_pid).map(|p| p.is_bot).unwrap_or(false);

            let child_state = self.processes.entry(fork.child_pid).or_insert(ProcessState {
                pid: fork.child_pid,
                comm: String::new(),
                events: VecDeque::new(),
                is_bot: parent_is_bot,
            });

            if parent_is_bot {
                child_state.is_bot = true;
                return Some(fork.child_pid);
            }
            return None;
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            comm: String::new(),
            events: VecDeque::new(),
            is_bot: false,
        });

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();
                if comm.contains("chromium") || comm.contains("firefox") || comm.contains("headless") || comm.contains("openclaw") {
                    state.events.push_back(EventRecord {
                        timestamp: now,
                        points: 50,
                    });
                }
            }
            EVENT_TYPE_CONNECT => {
                state.events.push_back(EventRecord {
                    timestamp: now,
                    points: 10,
                });
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".txt") || filename.ends_with(".doc") {
                    state.events.push_back(EventRecord {
                        timestamp: now,
                        points: 20,
                    });
                }
            }
            _ => {}
        }

        // Clean up old events
        while let Some(e) = state.events.front() {
            if now.duration_since(e.timestamp) > self.window_duration {
                state.events.pop_front();
            } else {
                break;
            }
        }

        if !state.is_bot && Self::calculate_score(state, self.window_duration) >= self.threshold {
            state.is_bot = true;
            Some(state.pid)
        } else if state.is_bot {
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
    fn test_sliding_window() {
        let mut analyzer = Analyzer::new(30);
        let pid = 1234;

        let event = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            data: EventData {
                connect: ConnectEvent { pid, addr: 0, port: 0 }
            }
        };

        // 3 connections = 30 points
        analyzer.handle_event(event);
        analyzer.handle_event(event);
        assert_eq!(analyzer.handle_event(event), Some(pid));
    }

    #[test]
    fn test_fork_inheritance() {
        let mut analyzer = Analyzer::new(50);
        let parent_pid = 1234;
        let child_pid = 5678;

        // Make parent a bot
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: parent_pid,
            data: EventData {
                exec: ExecEvent { pid: parent_pid, tgid: parent_pid, comm: [0; 16] }
            }
        };
        let comm = b"chromium\0";
        unsafe { event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(event);

        // Fork
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: parent_pid,
            data: EventData {
                fork: ForkEvent { parent_pid, child_pid }
            }
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(child_pid));
    }
}
