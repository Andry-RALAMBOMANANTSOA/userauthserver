use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::{handle, AggregatedMessage};
use futures_util::StreamExt as _;
use tokio::time::{Duration, Instant, interval};
use crate::shared::*;
use crate::function::*;

// Define a type for our WebSocket connections map


// Enum to differentiate connection types
enum ConnectionType {
    News,
    UserMessage {
        user_message_map: UserMessageMap,
        id_user: i64,
        user_message_sessions: UserMessageSessions,
        user_message_sessions_inv: UserMessageSessionsInv,
    },
}

// WebSocket Connection Handler
pub struct WebSocketConnection {
    connection_type: ConnectionType,
    ws_connections: WsConnections,
  
}

impl WebSocketConnection {
    async fn handle_ws(
        self,
        mut session: actix_ws::Session,
        mut stream: impl futures_util::Stream<Item = Result<AggregatedMessage, actix_ws::ProtocolError>> + Unpin,
        ws_connections: WsConnections,
    ) {
        // Generate a unique ID for each WebSocket connection
        let session_id = uuid::Uuid::new_v4().to_string();

        // Store connection without a user ID
        self.ws_connections.insert(session_id.clone(), session.clone());

        if let ConnectionType::UserMessage { id_user, user_message_sessions,  user_message_sessions_inv, .. } = &self.connection_type {
            user_message_sessions
                .entry(*id_user)
                .or_insert_with(Vec::new)
                .push(session_id.clone());

                user_message_sessions_inv.insert(session_id.clone(), *id_user);
        }

        // Create a ticker that ticks every minute
        let mut ticker = interval(Duration::from_secs(60));
        let mut last_ping = Instant::now();  // Record the last time a ping was received

        // Handle incoming messages
        loop {
            tokio::select! {
                // Handle WebSocket messages
                Some(msg) = stream.next() => {
                    match msg {
                        Ok(AggregatedMessage::Text(text)) => {
                            println!("Received from client: {}", text);
                            
                            // Handle ping message from the client
                            if text == r#"{"type":"ping"}"# {
                                last_ping = Instant::now();  // Update last ping time
                                session.text(r#"{"type":"pong"}"#).await.unwrap();
                              } else if text == r#"{"type":"close"}"# {
                                // Handle close message from the client
                                println!("Client requested connection close.");
                                self.remove_session(&ws_connections, session_id.clone());
                                    // Use a scoped lock to remove the session_id from ws_connections
                                    
                                break;
                            } else {
                                session.text(text).await.unwrap();
                            }
                        }
                        Ok(AggregatedMessage::Binary(bin)) => {
                            println!("Received binary from client");
                            session.binary(bin).await.unwrap();
                        }
                        Ok(AggregatedMessage::Ping(msg)) => {
                            println!("Received ping from client");
                            last_ping = Instant::now();  // Update last ping time
                            session.pong(&msg).await.unwrap();
                        }
                        Ok(_) => {}
                        Err(err) => {
                            println!("WebSocket error: {:?}", err);
                            break;
                        }
                    }
                },

                // Check if 5 minutes have passed without receiving a ping
                _ = ticker.tick() => {
                    if last_ping.elapsed() > Duration::from_secs(60) {  // 5 minutes
                        println!("No ping received from client for 5 minutes, closing connection.");
                        self.remove_session(&ws_connections,session_id.clone());
                        break;
                    }
                },
            }
        }

        self.remove_session(&ws_connections, session_id);
       
    
    }
    fn remove_session(&self, ws_connections: &WsConnections, session_id: String) {
        // Remove the session ID from ws_connections
        ws_connections.remove(&session_id);

        // Handle specific connection types for user messages
        if let ConnectionType::UserMessage { user_message_sessions, user_message_sessions_inv, .. } = &self.connection_type {
            // First, remove the session_id from user_message_sessions_inv
           
            if let Some((_,id_user)) = user_message_sessions_inv.remove(&session_id) {
                // Then, remove the session_id from user_message_sessions
                let mut is_sessions_empty = false;
                if let Some(mut sessions) = user_message_sessions.get_mut(&id_user) {
                    sessions.retain(|sid| sid != &session_id);
                   
                    if sessions.is_empty() {
                       is_sessions_empty = true;
                    }

                }
                if is_sessions_empty {
                    user_message_sessions.remove(&id_user);
                    
                }
            }
           
        }
    }
}



// Specific handlers for different types of connections

// Handler for public news WebSocket
pub async fn news_handler(
    req: HttpRequest,
    stream: web::Payload,
    ws_connections: web::Data<WsConnections>,
) -> Result<HttpResponse, Error> {
    // Initialize WebSocket handling
    let (res, session, stream) = handle(&req, stream)?;

    // Aggregate message continuations for processing as complete messages
    let aggregated_stream = stream
        .aggregate_continuations()
        .max_continuation_size(2_usize.pow(20));

    let ws = WebSocketConnection {
        connection_type: ConnectionType::News,
        ws_connections: ws_connections.get_ref().clone(),
    };

    // Spawn the async task to handle WebSocket
    actix_web::rt::spawn(ws.handle_ws(session, aggregated_stream, ws_connections.get_ref().clone()));

    Ok(res)
}

// Handler for user message WebSocket
pub async fn user_message_handler(
    req: HttpRequest,
    stream: web::Payload,
    ws_connections: web::Data<WsConnections>,
    user_message_map: web::Data<UserMessageMap>,
    user_message_session: web::Data<UserMessageSessions>,
    user_message_session_inv: web::Data<UserMessageSessionsInv>,
) -> Result<HttpResponse, Error> {
   
    // Extract and print cookies
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => return Ok(HttpResponse::Unauthorized().finish()),
    };

    // Initialize WebSocket handling
    let (res, mut session, stream) = handle(&req, stream)?;

    // Aggregate message continuations for processing as complete messages
    let aggregated_stream = stream
        .aggregate_continuations()
        .max_continuation_size(2_usize.pow(20));

    // Lock the user message map and retrieve the message count
    let (_,message_count) = user_message_map.remove(&id_user).unwrap_or((id_user, 0));
   
    // Send the message count to the client
    let message_count_message = serde_json::json!({
        "type": "initial_message_count",
        "count": message_count
    }).to_string();
    match session.text(message_count_message).await {
        Ok(_) => {}
        Err(err) => println!("Failed to send initial message count: {:?}", err),
    }

    let ws = WebSocketConnection {
        connection_type: ConnectionType::UserMessage {
            user_message_map: user_message_map.get_ref().clone(),
            id_user,
            user_message_sessions: user_message_session.get_ref().clone(),
            user_message_sessions_inv: user_message_session_inv.get_ref().clone(),
        },
        ws_connections: ws_connections.get_ref().clone(),
    };

    // Spawn the async task to handle WebSocket
    
    actix_web::rt::spawn(ws.handle_ws(session, aggregated_stream, ws_connections.get_ref().clone()));

    Ok(res)
}

