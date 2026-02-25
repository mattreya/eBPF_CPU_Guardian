use std::collections::HashMap;
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN, EVENT_TYPE_FORK};

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
    pub enforced: bool,
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
            let (parent_score, parent_comm, parent_enforced) = if let Some(parent) = self.processes.get(&fork.parent_pid) {
                (parent.score, parent.comm.clone(), parent.enforced)
            } else {
                (0, String::new(), false)
            };

            let child_state = self.processes.entry(fork.child_pid).or_insert(ProcessState {
                pid: fork.child_pid,
                score: parent_score,
                comm: parent_comm,
                enforced: parent_enforced,
            });

            // If parent was already enforced, we should enforce child immediately
            if child_state.enforced {
                return Some(fork.child_pid);
            }

            // If parent wasn't enforced but parent_score >= threshold (shouldn't happen often but still)
            if child_state.score >= self.threshold {
                child_state.enforced = true;
                return Some(fork.child_pid);
            }

            return None;
        }

        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            score: 0,
            comm: String::new(),
            enforced: false,
        });

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                let filename = std::str::from_utf8(&exec.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));

                state.comm = comm.to_string();

                let lower_comm = comm.to_lowercase();
                let lower_filename = filename.to_lowercase();

                if lower_comm.contains("chromium") || lower_comm.contains("firefox") ||
                   lower_comm.contains("headless") || lower_comm.contains("openclaw") ||
                   lower_comm.contains("clawbot") || lower_comm.contains("bot") ||
                   lower_filename.contains("chromium") || lower_filename.contains("firefox") ||
                   lower_filename.contains("bot")
                {
                    state.score += 50;
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
            }
            _ => {}
        }

        if state.score >= self.threshold && !state.enforced {
            state.enforced = true;
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
                    filename: [0; 64],
                },
            },
        };

        let comm = b"chromium\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }

        assert_eq!(analyzer.handle_event(event), Some(1234));
        // Redundant event should not trigger enforcement again
        assert_eq!(analyzer.handle_event(event), None);
    }

    #[test]
    fn test_fork_inheritance() {
        let mut analyzer = Analyzer::new(50);

        // Setup a bot
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 1000,
            data: EventData {
                exec: ExecEvent {
                    pid: 1000,
                    tgid: 1000,
                    comm: [0; 16],
                    filename: [0; 64],
                },
            },
        };
        let comm = b"openclaw\0";
        unsafe {
            event.data.exec.comm[..comm.len()].copy_from_slice(comm);
        }
        analyzer.handle_event(event);

        // Fork
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
    }
}
