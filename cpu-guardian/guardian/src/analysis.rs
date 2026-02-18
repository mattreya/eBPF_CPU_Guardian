use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use guardian_common::{
    GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK
};

const WINDOW_DURATION: Duration = Duration::from_secs(10);

pub struct EventRecord {
    pub timestamp: Instant,
    pub score: u32,
}

pub struct ProcessState {
    pub pid: u32,
    pub comm: String,
    pub is_bot: bool,
    pub events: VecDeque<EventRecord>,
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
            let is_bot = self.processes.get(&fork.parent_pid)
                .map(|p| p.is_bot)
                .unwrap_or(false);

            let child_state = ProcessState {
                pid: fork.child_pid,
                comm: String::new(),
                is_bot,
                events: VecDeque::new(),
            };

            if is_bot {
                self.processes.insert(fork.child_pid, child_state);
                return Some(fork.child_pid);
            }

            self.processes.insert(fork.child_pid, child_state);
            return None;
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            comm: String::new(),
            is_bot: false,
            events: VecDeque::new(),
        });

        if state.is_bot {
            return None; // Already detected
        }

        let now = Instant::now();
        let mut event_score = 0;

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();
                if comm.contains("headless") || comm.contains("openclaw") || comm.contains("clawbot") {
                    event_score += 50;
                }
            }
            EVENT_TYPE_CONNECT => {
                event_score += 10;
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".doc") || filename.ends_with(".docx") {
                    event_score += 20;
                }
            }
            _ => {}
        }

        if event_score > 0 {
            state.events.push_back(EventRecord {
                timestamp: now,
                score: event_score,
            });
        }

        // Clean up old events and calculate current score
        while let Some(e) = state.events.front() {
            if now.duration_since(e.timestamp) > WINDOW_DURATION {
                state.events.pop_front();
            } else {
                break;
            }
        }

        let total_score: u32 = state.events.iter().map(|e| e.score).sum();

        if total_score >= self.threshold {
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
    fn test_bot_detection_by_name() {
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
    fn test_bot_detection_by_behavior() {
        let mut analyzer = Analyzer::new(50);

        // 3 connect events (30 points) + 1 open doc event (20 points) = 50 points
        for _ in 0..3 {
            let event = GuardianEvent {
                event_type: EVENT_TYPE_CONNECT,
                pid: 1234,
                data: EventData {
                    connect: ConnectEvent { pid: 1234, addr: 0, port: 0 },
                },
            };
            analyzer.handle_event(event);
        }

        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_OPEN,
            pid: 1234,
            data: EventData {
                open: OpenEvent { pid: 1234, filename: [0; 64] },
            },
        };
        let filename = b"secret.pdf\0";
        unsafe {
            event.data.open.filename[..filename.len()].copy_from_slice(filename);
        }

        assert_eq!(analyzer.handle_event(event), Some(1234));
    }

    #[test]
    fn test_fork_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // Detect parent as bot
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 1234,
            data: EventData {
                exec: ExecEvent { pid: 1234, tgid: 1234, comm: [0; 16] },
            },
        };
        let comm = b"openclaw\0";
        unsafe { event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(event);

        // Fork
        let event_fork = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: 1234,
            data: EventData {
                fork: ForkEvent { parent_pid: 1234, child_pid: 5678 },
            },
        };

        assert_eq!(analyzer.handle_event(event_fork), Some(5678));

        // Verify child is marked as bot
        let child_state = analyzer.processes.get(&5678).unwrap();
        assert!(child_state.is_bot);
    }
}
