use std::collections::HashMap;
use guardian_common::{GuardianEvent, EVENT_TYPE_EXEC, EVENT_TYPE_CONNECT, EVENT_TYPE_OPEN};

pub struct ProcessState {
    pub pid: u32,
    pub score: u32,
    pub comm: String,
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
        let state = self.processes.entry(event.pid).or_insert(ProcessState {
            pid: event.pid,
            score: 0,
            comm: String::new(),
        });

        match event.event_type {
            EVENT_TYPE_EXEC => {
                let exec = unsafe { event.data.exec };
                let comm = std::str::from_utf8(&exec.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                state.comm = comm.to_string();
                if comm.contains("chromium") || comm.contains("firefox") || comm.contains("headless") {
                    state.score += 50;
                }
                if comm.contains("python") || comm.contains("node") {
                    state.score += 20;
                }
            }
            EVENT_TYPE_CONNECT => {
                state.score += 10;
            }
            EVENT_TYPE_OPEN => {
                let open = unsafe { event.data.open };
                let filename = std::str::from_utf8(&open.filename)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if filename.ends_with(".pdf") || filename.ends_with(".txt") ||
                   filename.ends_with(".doc") || filename.ends_with(".docx") ||
                   filename.contains(".config/chromium") {
                    state.score += 15;
                }
            }
            _ => {}
        }

        if state.score >= self.threshold {
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
    fn test_multiple_events() {
        let mut analyzer = Analyzer::new(100);

        // 1. Python process starts
        let mut event = GuardianEvent {
            event_type: EVENT_TYPE_EXEC,
            pid: 5678,
            data: EventData {
                exec: ExecEvent {
                    pid: 5678,
                    tgid: 5678,
                    comm: [0; 16],
                },
            },
        };
        let comm = b"python\0";
        unsafe { event.data.exec.comm[..comm.len()].copy_from_slice(comm); }
        assert_eq!(analyzer.handle_event(event), None); // Score 20

        // 2. Opens 4 PDF files
        for _ in 0..4 {
            let mut open_event = GuardianEvent {
                event_type: EVENT_TYPE_OPEN,
                pid: 5678,
                data: EventData {
                    open: OpenEvent {
                        pid: 5678,
                        filename: [0; 64],
                    },
                },
            };
            let file = b"paper.pdf\0";
            unsafe { open_event.data.open.filename[..file.len()].copy_from_slice(file); }
            assert_eq!(analyzer.handle_event(open_event), None); // Score 20 + 4*15 = 80
        }

        // 3. Connects to network twice
        let connect_event = GuardianEvent {
            event_type: EVENT_TYPE_CONNECT,
            pid: 5678,
            data: EventData {
                connect: ConnectEvent {
                    pid: 5678,
                    addr: 0,
                    port: 80,
                },
            },
        };
        assert_eq!(analyzer.handle_event(connect_event), None); // Score 80 + 10 = 90
        assert_eq!(analyzer.handle_event(connect_event), Some(5678)); // Score 90 + 10 = 100 -> Detected!
    }
}
