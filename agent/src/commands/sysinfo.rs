use crate::CommandExecutor;
use std::collections::HashMap;
use std::io::Error;
use sysinfo::{System, SystemExt};

pub struct SysinfoCommandExecutor;

impl CommandExecutor for SysinfoCommandExecutor {
    fn execute(&self, _args: &str, _data: &mut HashMap<String, String>) -> Result<String, Error> {
        // Please note that we use "new_all" to ensure that all list of
        // components, network interfaces, disks and users are already
        // filled!
        let mut sys = System::new_all();

        // First we update all information of our `System` struct.
        sys.refresh_all();

        let mut output = String::new();

        output.push_str("=> system:\n");
        // RAM and swap information:
        output.push_str(&format!("Total memory: {} bytes\n", sys.total_memory()));
        output.push_str(&format!("Used memory : {} bytes\n", sys.used_memory()));
        output.push_str(&format!("Total swap  : {} bytes\n", sys.total_swap()));
        output.push_str(&format!("Used swap   : {} bytes\n", sys.used_swap()));

        // Display system information:
        output.push_str(&format!("System name:             {:?}\n", sys.name()));
        output.push_str(&format!(
            "System kernel version:   {:?}\n",
            sys.kernel_version()
        ));
        output.push_str(&format!(
            "System OS version:       {:?}\n",
            sys.os_version()
        ));
        output.push_str(&format!("System host name:        {:?}\n", sys.host_name()));

        // Number of CPUs:
        output.push_str(&format!("CPUs count: {}\n", sys.cpus().len()));

        // Disks' information:
        output.push_str("=> disks:\n");
        for disk in sys.disks() {
            output.push_str(&format!("{:?}\n", disk));
        }

        Ok(output)
    }
}
