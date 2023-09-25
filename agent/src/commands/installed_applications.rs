use crate::CommandExecutor;
use std::collections::HashMap;
use std::io::Error;

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use winreg::enums::*;
    use winreg::RegKey;

    pub fn list_installed_applications() -> Result<String, Error> {
        // Connect to the Uninstall registry key where most installed applications are listed.
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let software_key = hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            KEY_READ,
        )?;

        let mut result = String::new();

        // Iterate through the subkeys (application entries) and add their display names to the result.
        for subkey in software_key.enum_keys() {
            if let Ok(key_name) = subkey {
                let subkey = software_key.open_subkey_with_flags(&key_name, KEY_READ)?;
                let display_name: String = subkey.get_value("DisplayName")?;
                if !display_name.is_empty() {
                    result += &display_name;
                    result += "\n";
                }
            }
        }

        Ok(result)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub fn list_installed_applications() -> Result<String, Error> {
        // Use the "ls" command to list installed applications on macOS.
        let output = Command::new("ls").arg("/Applications").output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stripped_output = strip_app_extension(&stdout);
            Ok(stripped_output)
        } else {
            eprintln!("Failed to list installed applications on macOS");
            Err(Error::new(
                std::io::ErrorKind::Other,
                "Failed to list applications",
            ))
        }
    }

    fn strip_app_extension(input: &str) -> String {
        input
            .lines()
            .map(|line| {
                if line.ends_with(".app") {
                    line.trim_end_matches(".app")
                } else {
                    line
                }
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;

    pub fn list_installed_applications() -> Result<String, Error> {
        // Use a package manager command like "dpkg -l" on Debian-based systems
        // to list installed applications on Linux.
        let output = Command::new("dpkg").arg("-l").output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.into_owned())
        } else {
            eprintln!("Failed to list installed applications on Linux");
            Err(Error::new(
                std::io::ErrorKind::Other,
                "Failed to list applications",
            ))
        }
    }
}

pub struct InstalledApplicationsCommandExecutor;

impl CommandExecutor for InstalledApplicationsCommandExecutor {
    fn execute(&self, _args: &str, _data: &mut HashMap<String, String>) -> Result<String, Error> {
        let mut result = String::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(windows_result) = windows::list_installed_applications() {
                result += &windows_result;
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(macos_result) = macos::list_installed_applications() {
                result += &macos_result;
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(linux_result) = linux::list_installed_applications() {
                result += &linux_result;
            }
        }

        Ok(result)
    }
}
