use std::fs;
use std::path::{PathBuf};
use log::{info, debug};

pub struct CgroupManager {
    base_path: PathBuf,
}

impl CgroupManager {
    pub fn new() -> Self {
        let base_path = PathBuf::from("/sys/fs/cgroup/guardian");
        if !base_path.exists() {
            if let Err(e) = fs::create_dir_all(&base_path) {
                eprintln!("Failed to create cgroup directory {}: {}", base_path.display(), e);
            } else {
                info!("Created cgroup base directory: {}", base_path.display());
            }
        }
        Self { base_path }
    }

    pub fn apply_limit(&self, pid: u32, cpu_percentage: u32) -> std::io::Result<()> {
        let bot_cgroup = self.base_path.join(format!("bot_{}", pid));
        if !bot_cgroup.exists() {
            fs::create_dir(&bot_cgroup)?;
            debug!("Created cgroup: {}", bot_cgroup.display());
        }

        // Set CPU limit: cpu.max contains "max period"
        // 100000 is usually the default period (100ms) in microseconds
        let period: u32 = 100000;
        let max = (period * cpu_percentage) / 100;

        fs::write(bot_cgroup.join("cpu.max"), format!("{} {}", max, period))?;
        debug!("Set CPU limit to {}/{} for PID {}", max, period, pid);

        // Move process to cgroup
        fs::write(bot_cgroup.join("cgroup.procs"), pid.to_string())?;
        info!("Moved PID {} to cgroup {}", pid, bot_cgroup.display());

        Ok(())
    }
}
