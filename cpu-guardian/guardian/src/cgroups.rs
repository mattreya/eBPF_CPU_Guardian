use std::fs;
use std::path::PathBuf;
use log::warn;

pub struct CgroupManager {
    base_path: PathBuf,
}

impl CgroupManager {
    pub fn new() -> Self {
        // Initialize cgroup v2 for CPU controller
        if let Err(e) = fs::write("/sys/fs/cgroup/cgroup.subtree_control", "+cpu") {
            warn!("Failed to enable cpu controller in root cgroup: {}", e);
        }

        let base_path = PathBuf::from("/sys/fs/cgroup/guardian");
        if !base_path.exists() {
            if let Err(e) = fs::create_dir_all(&base_path) {
                warn!("Failed to create guardian cgroup directory: {}", e);
            }
        }

        if let Err(e) = fs::write(base_path.join("cgroup.subtree_control"), "+cpu") {
            warn!("Failed to enable cpu controller in guardian cgroup: {}", e);
        }

        Self { base_path }
    }

    pub fn apply_limit(&self, pid: u32, cpu_percentage: u32) -> std::io::Result<()> {
        let bot_cgroup = self.base_path.join(format!("bot_{}", pid));
        if !bot_cgroup.exists() {
            fs::create_dir(&bot_cgroup)?;
        }

        // Set CPU limit: cpu.max contains "max period"
        // 100000 is usually the default period (100ms)
        let period = 100000;
        let max = (period * cpu_percentage) / 100;

        fs::write(bot_cgroup.join("cpu.max"), format!("{} {}", max, period))?;

        // Move process to cgroup
        fs::write(bot_cgroup.join("cgroup.procs"), pid.to_string())?;

        Ok(())
    }
}
