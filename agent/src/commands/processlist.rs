use crate::CommandExecutor;
use std::collections::HashMap;
use std::io::Error;
use sysinfo::{ProcessExt, System, SystemExt};

pub struct ProcessListCommandExecutor;

impl CommandExecutor for ProcessListCommandExecutor {
    fn execute(&self, _args: &str, _data: &mut HashMap<String, String>) -> Result<String, Error> {
        // Please note that we use "new_all" to ensure that all list of
        // components, network interfaces, disks and users are already
        // filled!
        let mut sys = System::new_all();

        // First we update all information of our `System` struct.
        sys.refresh_all();

        let mut output = String::new();

        // Display processes ID, name na disk usage:
        for (pid, process) in sys.processes() {
            output.push_str(&format!("[{}] {}\n", pid, process.name()));
        }

        // In case of success, return the output as a String.
        Ok(output)
    }
}
