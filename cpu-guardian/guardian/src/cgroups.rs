use std::fs;
use std::path::PathBuf;

pub struct CgroupManager {
    base_path: PathBuf,
}

impl CgroupManager {
    pub fn new() -> Self {
        let base_path = PathBuf::from("/sys/fs/cgroup/guardian");

        // Enable CPU controller in root cgroup subtree_control if it's not already enabled
        let root_control = PathBuf::from("/sys/fs/cgroup/cgroup.subtree_control");
        if root_control.exists() {
            let content = fs::read_to_string(&root_control).unwrap_or_default();
            if !content.contains("cpu") {
                let _ = fs::write(&root_control, "+cpu");
            }
        }

        if !base_path.exists() {
            fs::create_dir_all(&base_path).expect("Failed to create cgroup directory");
        }

        // Enable CPU controller in guardian cgroup subtree_control
        let guardian_control = base_path.join("cgroup.subtree_control");
        if guardian_control.exists() {
            let content = fs::read_to_string(&guardian_control).unwrap_or_default();
            if !content.contains("cpu") {
                let _ = fs::write(&guardian_control, "+cpu");
            }
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
