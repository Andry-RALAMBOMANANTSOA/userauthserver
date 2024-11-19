use crate::structs::*;
use rand::Rng;
use chrono::{DateTime, Utc,SecondsFormat};
use uuid::Uuid;
use chrono_tz::Tz;
use crate::shared::*;
use reqwest::Client;
use serde_json::json;
use bcrypt::{hash, DEFAULT_COST};
use actix_web::HttpRequest;
use jsonwebtoken::{encode,decode,Header,EncodingKey, DecodingKey, Validation};
use mongodb::{bson::doc, Database,bson, error::Result as MongoResult};
use mongodb::bson::Document;
use serde::{Deserialize, Serialize};
use mongodb::results::UpdateResult;
use mongodb::error::Error;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use aes_gcm::{
    aead::{Aead, AeadCore,KeyInit, OsRng},
    Aes256Gcm,Key, Nonce // Or `Aes128Gcm`
};
use futures::stream::FuturesUnordered;
use std::sync::{Arc};
use crate::websocket::*;
use actix_ws::Session;
use tokio::sync::Mutex;
use futures::stream::StreamExt;
use google_authenticator::GoogleAuthenticator;
use std::env;
use std::collections::HashMap;
use mongodb::bson::DateTime as BsonDateTime;
use tokio::sync::mpsc;
use hex;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rmp_serde::{Serializer, Deserializer};
//use std::error::Error;


pub fn month_to_french(month: &str) -> &str {
    let month_map: HashMap<&str, &str> = [
        ("January", "Janvier"), ("February", "Février"), ("March", "Mars"),
        ("April", "Avril"), ("May", "Mai"), ("June", "Juin"),
        ("July", "Juillet"), ("August", "Août"), ("September", "Septembre"),
        ("October", "Octobre"), ("November", "Novembre"), ("December", "Décembre"),
    ].iter().cloned().collect();
    
    month_map.get(month).unwrap_or(&month)
}
pub fn ms_res(message: &str, success: bool) -> MSResponse {
    MSResponse {
        message: message.to_string(),
        success,
    }
}
pub fn ms_res_json(data: &serde_json::Value, success: bool) -> MSResponseJson {
    MSResponseJson {
        data: data.clone(),
        success,
    }
}
pub fn ms_res_with_data(data: &serde_json::Value, success: bool,message:String) -> MSResponseData {
    MSResponseData {
        message,
        success,
        data: data.clone(), // Include data in the response
        
    }
}
pub fn fa_res_with_data(data: &serde_json::Value, success: bool,qrurl:String,qrsecret:String) -> FAResponseData {
    FAResponseData {
        qrurl,
        qrsecret,
        success,
        data: data.clone(), // Include data in the response
    }
}

pub fn gen_code() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen_range(100000..=999999)
}

pub async fn gencode_mail(user_id: i64,dest_mail:String,nom:String,prenom:String) -> Result<(), Box<dyn std::error::Error>> {
    let code_duration: i64 = match env::var("CODE_DURATION") {
        Ok(durat) => durat.parse().map_err(|e| {
            eprintln!("CODE_DURATION_PARSE_ERROR: {}", e);
            "Failed to parse CODE_DURATION"
        })?,
        Err(err) => {
            eprintln!("CODE_DURATION_ERROR: {}", err);
            return Err("Failed to retrieve CODE_DURATION".into());
        },
    };
    println!("code duration: {}", code_duration);
    let email_key = match env::var("EMAIL_KEY") {
        Ok(key) => key,
        Err(err) => {
            eprintln!("EMAIL_KEY_ERROR: {}", err);
            return Err("Failed to retrieve EMAIL_KEY".into());
            
        },
    };
    let app_name = match env::var("APP_NAME") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("APP_NAME_ERROR: {}", err);
            return Err("Failed to retrieve APP_NAME".into());
            
        },
    };
    let sender_mail = match env::var("SENDER_MAIL") {
        Ok(sender) => sender,
        Err(err) => {
            eprintln!("SENDER_MAIL_ERROR: {}", err);
            return Err("Failed to retrieve SENDER_MAIL".into());
            
        },
    };
    let mail_template = match env::var("MAIL_TEMPLATE") {
        Ok(template) => template,
        Err(err) => {
            eprintln!("MAIL_TEMPLATE_ERROR: {}", err);
            return Err("Failed to retrieve MAIL_TEMPLATE".into());
            
        },
    };
    let code = gen_code().to_string();
    let tz: Tz = "Europe/Moscow".parse().unwrap(); // UTC+3
    let now: DateTime<Tz> = Utc::now().with_timezone(&tz);
   
    let hashed_code = match hash(code.clone(), DEFAULT_COST) {
        Ok(hash) => hash,
        Err(err) => {
             eprintln!("Failed to hash code: {}", err);
             return Err("Failed to hash code".into());
        },
    };
    let mail_code = MailCode { code:hashed_code };

    MAIL_MAP.insert(user_id, mail_code,std::time::Duration::from_secs(code_duration as u64));

    let client = Client::new();
    

    let email_body = json!({
        "from": {
            "email": sender_mail,
            "name": &format!("{} Verification d'email", app_name),
        },
        "to": [{
            "email": dest_mail
        }],
        "template_uuid": mail_template,
        "template_variables": {
            "name": &format!("{} {}", nom,prenom),
            "company_info_name": app_name,
            "zip_code": code,
            "company_info_website_url":code_duration/60,
            "company_info_country": "Madagascar",
            "confirmation_timestamp": now.format("%Y-%m-%d %H:%M").to_string()
        }
    });

    client.post("https://send.api.mailtrap.io/api/send")
        .bearer_auth(email_key)
        .json(&email_body)
        .send()
        .await?;

    Ok(())
}


pub fn format_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return email.to_string(); // Return email as-is if it's not valid
    }
    let local_part = parts[0];
    let domain_part = parts[1];

    let local_part_len = local_part.len();
    let masked_local_part = if local_part_len > 2 {
        let last_two_chars = &local_part[local_part_len - 2..];
        let masked_part = format!("***{}", last_two_chars);
        format!("{}@{}", masked_part, domain_part)
    } else if local_part_len == 2 {
        let last_char = &local_part[1..];
        let masked_part = format!("*{}", last_char);
        format!("{}@{}", masked_part, domain_part)
    } else if local_part_len == 1 {
        format!("*{}@{}", local_part, domain_part)
    } else {
        email.to_string() // Return the email as-is if local part is empty
    };

    masked_local_part
}

pub fn decode_token(req: &HttpRequest) -> Option<i64> {
    let cookie_name = env::var("APP_NAME").ok()?;
    let cookie = req.cookie(&cookie_name)?;

    let token_value = cookie.value().to_string();
    let secret_key = env::var("TOKEN_SECRET").ok()?;

    let token_data: TokenData = decode::<TokenData>(
        &token_value,
        &DecodingKey::from_secret(secret_key.as_ref()),
        &Validation::default(),
    )
    .map(|decoded| decoded.claims)
    .ok()?;

    Some(token_data.id_user)
}
pub async fn fetch_document<T>(
    db: &Database,
    collection_name: &str,
    id_user: i64,
) -> Result<T, String>
where 
T: DeserializeOwned + Unpin + Debug + Send + Sync,
 {
    let collection = db.collection::<T>(collection_name);

    // Find the user by id_user
    let filter = doc! { "id_user": id_user };
    let document = collection
        .find_one(filter)
        .await
        .map_err(|err| format!("Failed to query the database: {}", err))?;

    match document {
        Some(doc) => Ok(doc),
        None => Err(format!("Document not found in collection '{}'", collection_name)),
    }
}

pub async fn fetch_all_documents<T>(
    db: &Database,
    collection_name: &str,
) -> Result<Vec<T>, String>
where
    T: DeserializeOwned + Unpin + Debug + Send + Sync,
{
    let collection = db.collection::<T>(collection_name);

    let cursor = collection
        .find(doc! {})
        .await
        .map_err(|err| format!("Failed to query the database: {}", err))?;

    let mut documents = Vec::new();
    let mut cursor_stream = cursor;

    while let Some(result) = cursor_stream.next().await {
        match result {
            Ok(doc) => {
                // Debug print to check what the document looks like
               // println!("Fetched document: {:?}", doc);
                documents.push(doc);
            },
            Err(err) => return Err(format!("Error fetching document: {}", err)),
        }
    }

    Ok(documents)
}
pub async fn fetch_all_documents_by_user<T>(
    db: &Database,
    collection_name: &str,
    id_user: i64,
) -> Result<Vec<T>, String>
where
    T: DeserializeOwned + Unpin + Debug + Send + Sync,
{
    let collection = db.collection::<T>(collection_name);

    // Create a filter to find documents where "id_user" matches the provided id_user
    let filter = doc! { "id_user": id_user };

    // Find documents that match the filter
    let cursor = collection
        .find(filter)
        .await
        .map_err(|err| format!("Failed to query the database: {}", err))?;

    let mut documents = Vec::new();
    let mut cursor_stream = cursor;

    while let Some(result) = cursor_stream.next().await {
        match result {
            Ok(doc) => {
                // Debug print to check what the document looks like
               
                documents.push(doc);
            },
            Err(err) => return Err(format!("Error fetching document: {}", err)),
        }
    }

    Ok(documents)
}

pub async fn fetch_document_string<T>(
    db: &Database,
    collection_name: &str,
    email: &str,
) -> Result<T, String>
where
    T: DeserializeOwned + Unpin + Debug + Send + Sync,
{
    let collection = db.collection::<T>(collection_name);

    // Find the document by email
    let filter = doc! { "email": email };
    let document = collection
        .find_one(filter)
        .await
        .map_err(|err| format!("Failed to query the database: {}", err))?;

    match document {
        Some(doc) => Ok(doc),
        None => Err(format!("Document not found in collection '{}'", collection_name)),
    }
}
pub async fn fetch_content<T>(
    db: &Database,
    collection_name: &str,
    title: &str,
) -> Result<T, String>
where
    T: DeserializeOwned + Unpin + Debug + Send + Sync,
{
    let collection = db.collection::<T>(collection_name);

    // Find the document by email
    let filter = doc! { "title": title };
    let document = collection
        .find_one(filter)
        .await
        .map_err(|err| format!("Failed to query the database: {}", err))?;

    match document {
        Some(doc) => Ok(doc),
        None => Err(format!("Document not found in collection '{}'", collection_name)),
    }
}

pub async fn update_user_bool(
    db: &Database,
    collection_name: &str,
    id_user: i64,
    field: &str,
    value: bool,
) -> Result<UpdateResult, String> {
    let collection: mongodb::Collection<User> = db.collection(collection_name);

    // Build the update document
    let update_doc = doc! { "$set": { field: value } };

    // Update the user document
    collection
        .update_one(doc! { "id_user": id_user }, update_doc)
        .await
        .map_err(|err| format!("Failed to update {} in database: {}", field, err))
}

pub async fn insert_document_collection<T>(
    db: &Database,
    collection_name: &str,
    item: &T,
) -> Result<(), Error>
where
    T: Serialize,
{
    let collection: mongodb::Collection<Document> = db.collection(collection_name);
    let doc = bson::to_document(item)?;
    collection.insert_one(doc).await?;
    Ok(())
}
pub async fn insert_user_message(
    db: &Database,
    collection_name: &str,
    id_user:i64,title:String,message:String
) -> Result<(), Error> {
    let bson_datetime = BsonDateTime::now();
    let bson_doc = doc! {
        "id_user": id_user,
        "date":bson_datetime,
        "title": title,
        "message": message,
        "date_str":Utc::now().to_rfc3339(),
    };
    let collection = db.collection(collection_name);
    //let doc = bson::to_document(&bson_doc)?;
    collection.insert_one(bson_doc).await?;
    Ok(())
}
pub async fn overwrite_document_collection<T>(
    db: &Database,
    collection_name: &str,
    item: &T,
    id_user: i64,
) -> Result<(), Error>
where
    T: Serialize,
{
    let collection = db.collection::<Document>(collection_name);

    // Serialize the item into a BSON document
    let doc = bson::to_document(item)?;

    // Define the filter to match the document with the specified user ID
    let filter = doc! { "id_user": id_user };

    // Perform the update operation, using the `replace_one` method to overwrite the document
    collection.replace_one(filter, doc).await?;

    Ok(())
}
pub async fn update_field_document<T>(
    db: &Database,
    collection_name: &str,
    user_id: i64,
    field_name: &str,
    field_value: &T,
) -> Result<(), Error>
where
    T: Serialize,
{
    let collection = db.collection::<mongodb::bson::Document>(collection_name);

    // Create a filter to find the document by user_id
    let filter = doc! { "id_user": user_id };

    // Create an update document to set the field value
    let update = doc! { "$set": { field_name: bson::to_bson(field_value)? } };

    // Perform the update operation
    collection.update_one(filter, update).await?;

    Ok(())
}
pub fn create_token(id_user: i64, token_duration: i64, secret_key: &str) -> Result<String, &'static str> {
    let now: DateTime<Utc> = Utc::now();
    let moscow: Tz = "Europe/Moscow".parse().unwrap();
    let moscow_time = now.with_timezone(&moscow);
    let issued_at = moscow_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let exp = (moscow_time + chrono::Duration::seconds(token_duration)).timestamp() as usize;
    let nonce = Uuid::new_v4().to_string();

    let token_data = TokenData {
        id_user,
        issued_at,
        exp,
        nonce,
    };

    let token = encode(
        &Header::default(),
        &token_data,
        &EncodingKey::from_secret(secret_key.as_ref()),
    ).map_err(|_| "Failed to generate token")?;

    Ok(token)
}
pub fn encryption(plaintext: &str,env_varkey:&str) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Retrieve the TOTP_KEY from the environment
    let env_key = match env::var(env_varkey) {
        Ok(key) => key,
        Err(err) => return Err(format!("Environment variable error: {}", err)),
    };

    // Convert the TOTP_KEY into a 32-byte key for AES256
    let mut key_bytes = [0u8; 32];
    let key_slice = env_key.as_bytes();
    let len = key_slice.len().min(32);
    key_bytes[..len].copy_from_slice(&key_slice[..len]);

    // Initialize the cipher with the key
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(&key);

    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the plaintext
    match cipher.encrypt(&nonce, plaintext.as_ref()) {
        Ok(ciphertext) => Ok((ciphertext, nonce.to_vec())),
        Err(err) => Err(format!("Encryption failed: {}", err)),
    }
}

pub fn decryption(
    cipher_secret: Vec<u8>,
    nonce_bytes: Vec<u8>,
    env_varkey:&str
) -> Result<String, String> {
    // Retrieve the TOTP key from environment variables
    let env_key = match env::var(env_varkey) {
        Ok(key) => key,
        Err(err) => {
            return Err(format!("Environment variable error: {}", err));
        }
    };

    // Convert the TOTP key into bytes
    let mut key_bytes = [0u8; 32];
    let key_slice = env_key.as_bytes();
    let len = key_slice.len().min(32);
    key_bytes[..len].copy_from_slice(&key_slice[..len]);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let mut nonce_array = [0u8; 12];
    let nonce_len = nonce_bytes.len().min(12);
    nonce_array[..nonce_len].copy_from_slice(&nonce_bytes[..nonce_len]);

    let nonce = Nonce::from_slice(&nonce_array);
    let cipher = Aes256Gcm::new(key);

    match cipher.decrypt(nonce, cipher_secret.as_ref()) {
        Ok(secret) => match String::from_utf8(secret) {
            Ok(secret_str) => Ok(secret_str),
            Err(err) => Err(format!("Error converting to UTF-8 string: {}", err)),
        },
        Err(err) => Err(format!("Encryption failed: {}", err)),
    }
}

pub fn verify_totp_code(secret_str: &str, code: &str) -> bool {
    let auth = GoogleAuthenticator::new();

    
    // Use UTC time zone
    let now: DateTime<Utc> = Utc::now();
 
    // Get the current time in seconds since the Unix epoch
    let current_time = now.timestamp() as u64;
 
    // Assuming a TOTP period of 30 seconds
    let time_slice = current_time / 30;


    auth.verify_code(secret_str, code, 1, time_slice)
}

pub fn generate_cookie(
    token_duration_env_name: &str,
    cookie_name_env_name: &str,
    secret_key_env_name: &str,
    id_user: i64,
    
) -> Result<String, String> {
    // Retrieve the token duration from environment variables
    let token_duration_env: i64 = match env::var(token_duration_env_name) {
        Ok(duration) => match duration.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                eprintln!("Failed to parse {}", token_duration_env_name);
                return Err("Internal server error".to_string());
            }
        },
        Err(_) => {
            eprintln!("{} must be set", token_duration_env_name);
            return Err("Internal server error".to_string());
        }
    };

    // Retrieve the cookie name from environment variables
    let cookie_name = match env::var(cookie_name_env_name) {
        Ok(name) => name,
        Err(err) => {
            eprintln!("{} error: {}", cookie_name_env_name, err);
            return Err("Internal server error".to_string());
        }
    };

    // Retrieve the secret key from environment variables
    let secret_key = match env::var(secret_key_env_name) {
        Ok(key) => key,
        Err(_) => {
            eprintln!("{} must be set", secret_key_env_name);
            return Err("Internal server error".to_string());
        }
    };

    // Create the token
    let token = match create_token(id_user, token_duration_env, &secret_key) {
        Ok(token) => token,
        Err(_) => return Err("Failed to generate token".to_string()),
    };

    // Calculate the token expiration
    let token_duration = chrono::Duration::seconds(token_duration_env);
    let expiration_date_utc = Utc::now() + token_duration;
    let expiration_str = expiration_date_utc.format("%a, %d %b %Y %H:%M:%S GMT").to_string();

    // Format the cookie string
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=None; Secure; Expires={}",
        cookie_name, token, expiration_str
    );

    Ok(cookie)
}

pub fn generate_cookie_del(
    cookie_name_env_name: &str,
) -> Result<String, String> {
    
    // Retrieve the cookie name from environment variables
    let cookie_name = match env::var(cookie_name_env_name) {
        Ok(name) => name,
        Err(err) => {
            eprintln!("{} error: {}", cookie_name_env_name, err);
            return Err("Internal server error".to_string());
        }
    };
    // Format the cookie string
    let cookie = format!(
        "{}=None; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=0 ",
        cookie_name, 
    );

    Ok(cookie)
}

pub async fn delete_id(
    collection_string:&str,
    db: &Database,
    id_user: i64
) -> Result<(), String> {
    // Retrieve the collection name from the environment
    let collection_name = match env::var(collection_string) {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_USER_LOGSTATE_ERROR: {}", err);
            return Err("Internal server error".to_string())
        }
    };

    let collection = db.collection::<mongodb::bson::Document>(&collection_name);

    match collection.delete_one(doc! { "id_user": id_user }).await {
        Ok(delete_result) => {
            if delete_result.deleted_count > 0 {
                // Document was deleted successfully
                Ok(())
            } else {
                // No document found with the given id_user
                Err("Vous êtes déjà déconnecté.".to_string())
            }
        }
        Err(err) => {
            eprintln!("Error deleting document: {}", err);
            Err("Internal server error".to_string())
        }
    }
}

pub async fn watch_news_collection(
    db: CompanyDb,
    collection_name: &str,
    ws_connections: WsConnections, // Add reference to ws_connections
) -> MongoResult<()> {
    let collection = db.db.collection::<Document>(collection_name);
    let mut change_stream = collection.watch().await?;

    while let Some(change) = change_stream.next().await {
        match change {
            Ok(change_event) => {
                if let Some(_document) = &change_event.full_document {
                    println!("Change detected: {:?}", change_event);

                    // Broadcast the change to all connected WebSocket clients
                    let msg = "news available".to_string();
                  

                    for mut session in ws_connections.iter_mut() {
                        let msg_clone = msg.clone();
                        
                            if let Err(e) = session.value_mut().text(msg_clone).await {
                                eprintln!("Failed to send message: {:?}", e);
                            }
                        
                    }

                }
            }
            Err(err) => eprintln!("Error processing change stream: {:?}", err),
        }
    }

    Ok(())
}
pub async fn watch_user_messages(
    db: UserDb,
    collection_name: &str,
    user_message_counts: UserMessageMap,
    user_message_sessions: UserMessageSessions, 
    ws_connections: WsConnections,
) -> MongoResult<()> {
    let collection = db.db.collection::<Document>(collection_name);
    let mut change_stream = collection.watch().await?;

    while let Some(change) = change_stream.next().await {
        match change {
            Ok(change_event) => {
                if let Some(document) = &change_event.full_document {
                    if let Some(user_id) = document.get_i64("id_user").ok() {
                        println!("Change detected for user_id: {}", user_id);
                      
                        match user_message_sessions.get(&user_id) {
                            Some(session_ids) => {
                                // User exists in UserMessageSessions, send message to all associated sessions
                                let msg = serde_json::json!({
                                    "type": "message_available",
                                }).to_string();

                                // Iterate over all session IDs associated with the user_id
                                for session_id in session_ids.iter() {
                                    let session_id = session_id.clone();
                                    let msg_clone = msg.clone();
                                    if let Some(mut session) = ws_connections.get_mut(&session_id) {
                                        let session = session.value_mut(); // Use `value` to get an immutable reference
                                        if let Err(e) = session.text(msg_clone).await {
                                            eprintln!("Failed to send message to session {}: {:?}", session_id, e);
                                        }
                                    } else {
                                        eprintln!("Session {} not found in ws_connections", session_id);
                                    }
                                }
                            }
                            None => {
                                // User does not exist in UserMessageSessions, increment the message count
                                let mut entry = user_message_counts.entry(user_id).or_insert(0);
                                *entry += 1;
                            }
                        }
                    } else {
                        eprintln!("Failed to get user_id from document");
                    }
                } else {
                    eprintln!("Full document not found in change event");
                }
            }
            Err(err) => eprintln!("Error processing change stream: {:?}", err),
        }
    }

    Ok(())
}
