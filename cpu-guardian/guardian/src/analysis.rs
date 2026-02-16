use std::collections::HashMap;
use std::time::{Instant, Duration};
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct EventRecord {
    pub timestamp: Instant,
    pub score: u32,
}

pub struct ProcessState {
    pub pid: u32,
    pub comm: String,
    pub events: Vec<EventRecord>,
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

    pub fn handle_event(&mut self, event: GuardianEvent) -> Option<u32> {
        let now = Instant::now();

        // Handle FORK separately to manage inheritance
        if event.event_type == EVENT_TYPE_FORK {
            let fork = unsafe { event.data.fork };
            let parent_is_bot = self.processes.get(&fork.parent_pid).map(|p| p.is_bot).unwrap_or(false);

            let child_state = self.processes.entry(fork.child_pid).or_insert_with(|| ProcessState {
                pid: fork.child_pid,
                comm: String::new(),
                events: Vec::new(),
                is_bot: parent_is_bot,
            });

            if parent_is_bot {
                child_state.is_bot = true;
                return Some(fork.child_pid);
            }
            return None;
        }

        let state = self.processes.entry(event.pid).or_insert_with(|| ProcessState {
            pid: event.pid,
            comm: String::new(),
            events: Vec::new(),
            is_bot: false,
        });

        if state.is_bot {
            return Some(state.pid);
        }

        let mut current_score = 0;
        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();

                if comm.contains("chromium") || comm.contains("firefox") ||
                   comm.contains("headless") || comm.contains("openclaw") {
                    current_score = 50;
                }
            }
            EVENT_TYPE_CONNECT => {
                current_score = 10;
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".txt") ||
                   filename.ends_with(".doc") || filename.ends_with(".docx") {
                    current_score = 20;
                }
            }
            _ => {}
        }

        if current_score > 0 {
            state.events.push(EventRecord {
                timestamp: now,
                score: current_score,
            });
        }

        // Clean up old events and calculate total score
        state.events.retain(|e| now.duration_since(e.timestamp) <= self.window_duration);
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
    fn test_scoring_and_window() {
        let mut analyzer = Analyzer::new(50);
        let pid = 1234;

        // 1. Initial event - not enough for threshold
        let event_connect = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            data: EventData { connect: ConnectEvent { pid, addr: 0, port: 0 } },
        };
        assert_eq!(analyzer.handle_event(event_connect), None);

        // 2. Another connect
        let event_connect = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            data: EventData { connect: ConnectEvent { pid, addr: 0, port: 0 } },
        };
        assert_eq!(analyzer.handle_event(event_connect), None);

        // 3. Document access (20 points)
        let mut event_open = GuardianEvent {
            event_type: EVENT_TYPE_OPEN,
            pid,
            data: EventData { open: OpenEvent { pid, filename: [0; 64] } },
        };
        let filename = b"test.pdf";
        unsafe { event_open.data.open.filename[..filename.len()].copy_from_slice(filename); }
        assert_eq!(analyzer.handle_event(event_open), None); // Total: 10 + 10 + 20 = 40

        // 4. One more connect (Total 50)
        let event_connect = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid,
            data: EventData { connect: ConnectEvent { pid, addr: 0, port: 0 } },
        };
        assert_eq!(analyzer.handle_event(event_connect), Some(pid));
    }

    #[test]
    fn test_inheritance() {
        let mut analyzer = Analyzer::new(50);
        let parent_pid = 1234;
        let child_pid = 5678;

        // Mark parent as bot
        let mut event_exec = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: parent_pid,
            data: EventData { exec: ExecEvent { pid: parent_pid, tgid: parent_pid, comm: [0; 16] } },
        };
        let comm = b"openclaw";
        unsafe { event_exec.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        analyzer.handle_event(event_exec); // Score 50, marked as bot

        // Fork
        let event_fork = GuardianEvent {
            event_type: EVENT_TYPE_FORK,
            pid: parent_pid,
            data: EventData { fork: ForkEvent { parent_pid, child_pid } },
        };
        assert_eq!(analyzer.handle_event(event_fork), Some(child_pid));
    }
}
