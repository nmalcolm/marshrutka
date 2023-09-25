use crate::CommandExecutor;
use std::collections::HashMap;
use std::io::Error;
use std::thread;
use std::time::Duration;
pub struct KillAgentCommandExecutor;

impl CommandExecutor for KillAgentCommandExecutor {
    fn execute(&self, _args: &str, _data: &mut HashMap<String, String>) -> Result<String, Error> {
        thread::spawn(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(kill_agent());
        });

        // In case of success, return the output as a String.
        Ok("killed agent".to_string())
    }
}

async fn kill_agent() {
    tokio::time::sleep(Duration::from_secs(5)).await;
    std::process::exit(0);
}
