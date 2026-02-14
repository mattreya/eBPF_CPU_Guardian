use std::collections::HashMap;
use guardian_common::{
    GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK
};

const WINDOW_NS: u64 = 10_000_000_000; // 10 seconds

pub struct EventRecord {
    pub timestamp_ns: u64,
    pub points: u32,
}

pub struct ProcessState {
    pub pid: u32,
    pub comm: String,
    pub is_bot: bool,
    pub events: Vec<EventRecord>,
    pub base_score: u32,
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
            let is_parent_bot = self.processes.get(&fork.parent_pid).map(|p| p.is_bot).unwrap_or(false);

            let child_state = self.processes.entry(fork.child_pid).or_insert(ProcessState {
                pid: fork.child_pid,
                comm: String::new(),
                is_bot: is_parent_bot,
                events: Vec::new(),
                base_score: 0,
            });

            if is_parent_bot {
                child_state.is_bot = true;
                return Some(fork.child_pid);
            }
            return None;
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            comm: String::new(),
            is_bot: false,
            events: Vec::new(),
            base_score: 0,
        });

        if state.is_bot {
            return Some(state.pid);
        }

        let mut points = 0;

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();
                if comm.contains("headless") || comm.contains("openclaw") || comm.contains("clawbot") || comm.contains("moltbot") {
                    state.base_score += 100;
                }
            }
            EVENT_TYPE_CONNECT => {
                points = 10;
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".doc") || filename.ends_with(".docx") {
                    points = 20;
                }
            }
            _ => {}
        }

        if points > 0 {
            state.events.push(EventRecord {
                timestamp_ns: event.timestamp_ns,
                points,
            });
        }

        // Prune old events
        let current_time = event.timestamp_ns;
        state.events.retain(|e| current_time.saturating_sub(e.timestamp_ns) < WINDOW_NS);

        let total_score = state.base_score + state.events.iter().map(|e| e.points).sum::<u32>();

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
    fn test_sliding_window() {
        let mut analyzer = Analyzer::new(30);
        let pid = 1234;

        // First connection at t=0
        let event1 = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            timestamp_ns: 0,
            data: EventData { connect: ConnectEvent { pid, addr: 0, port: 0 } },
        };
        assert_eq!(analyzer.handle_event(event1), None); // Score 10

        // Second connection at t=5s
        let event2 = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            timestamp_ns: 5_000_000_000,
            data: EventData { connect: ConnectEvent { pid, addr: 0, port: 0 } },
        };
        assert_eq!(analyzer.handle_event(event2), None); // Score 20

        // Third connection at t=11s (event1 should be pruned)
        let event3 = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            timestamp_ns: 11_000_000_000,
            data: EventData { connect: ConnectEvent { pid, addr: 0, port: 0 } },
        };
        assert_eq!(analyzer.handle_event(event3), None); // Score 20 (event2 + event3)

        // Add 2 more connections at t=11s
        analyzer.handle_event(event3); // Score 30 -> Bot!
        assert_eq!(analyzer.handle_event(event3), Some(pid));
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);
        let parent_pid = 1000;
        let child_pid = 2000;

        // Flag parent as bot
        let mut exec_event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: parent_pid,
            timestamp_ns: 0,
            data: EventData { exec: ExecEvent { pid: parent_pid, tgid: parent_pid, comm: [0; 16] } },
        };
        let comm = b"openclaw\0";
        unsafe { exec_event.data.exec.comm[..comm.len()].copy_from_slice(comm); }

        assert_eq!(analyzer.handle_event(exec_event), Some(parent_pid));

        // Fork child
        let fork_event = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: parent_pid,
            timestamp_ns: 100,
            data: EventData { fork: ForkEvent { parent_pid, child_pid } },
        };

        assert_eq!(analyzer.handle_event(fork_event), Some(child_pid));
    }
}
