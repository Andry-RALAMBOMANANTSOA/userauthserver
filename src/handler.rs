use actix_web::{rt::time, web,HttpRequest, HttpResponse, Responder};

use serde_json::json;
use mongodb::{Database,bson::doc,bson,Collection};
use mongodb::bson::DateTime as BsonDateTime;
use google_authenticator::{GoogleAuthenticator, ErrorCorrectionLevel};
use aes_gcm::{
    aead::{Aead, AeadCore,KeyInit, OsRng},
    Aes256Gcm,Key, Nonce // Or `Aes128Gcm`
};
use std::fs::File;
use std::io::Write;
//use futures_util::StreamExt;
use crate::structs::*;
use crate::function::*;
use crate::string_message::*;
use bcrypt::{hash, verify,DEFAULT_COST};
use rand::Rng;
use chrono::{DateTime, Utc, SecondsFormat,Duration,NaiveDateTime,Local,TimeZone};
use chrono_tz::Tz;
use ipgeolocate::{Locator, Service};
use std::sync::{Arc};
use std::{default, env};
use uuid::Uuid;
use actix_web::http::header::SET_COOKIE;
use actix_multipart::Multipart;
use futures_util::{StreamExt, SinkExt};
use std::fs::{create_dir_all};
use crate::shared::*;


pub async fn signup(data: web::Json<SignupData>, user_db: web::Data<UserDb>) -> impl Responder {
    let db: &Database = &user_db.db;
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let cookie_name = match env::var("APP_NAME") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("APP_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    
    // Check if the email already exists
    let email_exists = match db.collection::<User>(&collection_user).find_one(bson::doc! { "email": &data.email }).await {
        Ok(result) => result.is_some(),
        Err(_) => {
            eprintln!("DATABASE_FETCHING_FAILURE");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
   

    let mobile = match data.mobile.parse::<i32>() {
        Ok(mobile) => mobile,
        Err(_) => {
            eprintln!("FAILED TO PARSE MOBILE NUMBER");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let mobile_exists = match db.collection::<User>(&collection_user).find_one(bson::doc! { "mobile": mobile }).await {
        Ok(result) => result.is_some(),
        Err(_) => {
            eprintln!("DATABASE_FETCHING_FAILURE");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };

    if email_exists {
        return HttpResponse::BadRequest().json(ms_res("L'adresse Email existe déjà, connectez-vous!", false));
    }
    if mobile_exists {
        return HttpResponse::BadRequest().json(ms_res("Le numéro de téléphone existe déjà, connectez-vous!", false));
    }

    let service = Service::IpApi;
    let ip = &data.ip;
    let country = match Locator::get(ip, service).await {
        Ok(ip_info) => ip_info.country.to_string(),
        Err(error) => {
            println!("Error: {}", error);
            "Unknown".to_string()
        }
    };

    // Read allowed countries from the environment
    let allowed_countries: Vec<String> = env::var("ALLOWED_COUNTRY")
        .expect("ALLOWED_COUNTRY must be set")
        .split(':')
        .map(|s| s.to_string())
        .collect();

    // Check if the country is allowed
    if !allowed_countries.contains(&country) {
        return HttpResponse::BadRequest().json(ms_res(NCOUNTRY, false));
    }

    // Encrypt the password
    let id_user = rand::thread_rng().gen_range(1..=i64::MAX);
    let hashed_password = match hash(&data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("Failed to hash password: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let hashed_secret_word = match hash(&data.secret_word, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("Failed to hash secret word: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let (cryptpass, pass_nonce) = match encryption(&hashed_password,"PASS_KEY") {
        Ok(result) => result,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let (cryptsecretword, secretword_nonce) = match encryption(&hashed_secret_word,"SECRET_WORD_KEY") {
        Ok(result) => result,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };

    
    let now: DateTime<Utc> = Utc::now();
    let moscow: Tz = "Europe/Moscow".parse().unwrap();
    let moscow_time = now.with_timezone(&moscow);
    let formatted_date = moscow_time.to_rfc3339_opts(SecondsFormat::Secs, true);

    // Read the token duration from the environment
    let token_duration_env: i64 = match env::var("TOKEN_DURATION_BOTP") {
        Ok(duration) => match duration.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                eprintln!("Failed to parse TOKEN_DURATION");
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            },
        },
        Err(_) => {
            eprintln!("TOKEN_DURATION must be set");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
   
    let secret_key = match env::var("TOKEN_SECRET") {
        Ok(key) => key,
        Err(_) => {
            eprintln!("SECRET_KEY must be set");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
        Ok(message_coll) => message_coll,
        Err(_) => {
            eprintln!("User message collection must be set");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };

    let token = match create_token(id_user, token_duration_env, &secret_key) {
        Ok(token) => token,
        Err(_) => {
            eprintln!("Failed to generate token");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };

    // Insert new user
    let user = User {
        first_name: data.first_name.clone(),
        last_name: data.last_name.clone(),
        email: data.email.clone(),
        mobile,
        id_user,
        pays: country,
        active: true,
        created_at: formatted_date.clone(), // Set the created_at date
        registration_ip: data.ip.clone(),
        registration_device: data.device.clone(),
        registration_browser: data.browser.clone(),
        ..Default::default() // Use default values for the rest
    };
    let user_sensitive = UserSensitive {
        id_user,
        crypt_password: cryptpass,
        password_nonce:pass_nonce,
        secret_word_crypt:cryptsecretword,
        secret_word_nonce:secretword_nonce,
        ..Default::default() // Use default values for the rest
    };

    let token_duration = chrono::Duration::seconds(token_duration_env);
    let expiration_date_utc = Utc::now() + token_duration ;
    let expiration_str = expiration_date_utc.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=None; Secure; Expires={}",
        cookie_name,
        token,
        expiration_str
    );
    if let Err(err) = insert_document_collection(&db, &collection_user_sensitive, &user_sensitive).await {
        eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
    }
    
    if let Err(err) = insert_document_collection(&db, &collection_user, &user).await {
        eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
    }
    
    if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Inscription".to_string(), "Bienvenue chez your_company_name! Remplissez vos informations pour commencer à échanger.".to_string()).await {
        eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
    }
    
    // If all operations are successful
    HttpResponse::Ok()
        .append_header((SET_COOKIE, cookie))
        .json(json!({
            "success": true,
            "message": {
                "nextpath": SIGNUP_SUCCESS,
            }
        }))
   
    
   
}


pub async fn activateaccount( user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };


    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    if user.mail_verified {
        return HttpResponse::Ok().json(ms_res(EMAIL_ALREADY, false));
    }
    let dest_mail = user.email;
    let nom = user.first_name;
    let prenom = user.last_name;
   
    
    let code_duration: i64 = match env::var("CODE_DURATION") {
        Ok(durat) =>match durat.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                eprintln!("Failed to parse CODE_DURATION");
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            },
        },
        Err(_) => {
            eprintln!("CODE_DURATION must be set");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let expiration = Utc::now() + chrono::Duration::seconds(code_duration) ;
    let exp_timestamp = expiration.timestamp(); 

    if let Err(e) = gencode_mail(id_user, dest_mail.clone(), nom, prenom).await {
        eprintln!("Failed to generate and send email code: {}", e);
        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
    }
    HttpResponse::Ok()
                .json(json!({
                    "success": true,
                    "message": {
                        "Email": format_email(&dest_mail.clone()),
                        "expiration": exp_timestamp,
                        
                    }
                }))
}

pub async fn mailcodevalidation(data: web::Json<EmailValidationData>, user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    if user.mail_verified {
        return HttpResponse::Ok().json(ms_res(EMAIL_ALREADY, false));
    }
    

    let mail_code_option = MAIL_MAP.get(&id_user);
    let mail_code = match mail_code_option {
        Some(code) => code,
        None => {
            return HttpResponse::BadRequest().json(ms_res(EXMAILCODE, false));
        }
    };

    match verify(&data.code, &mail_code.code) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::BadRequest().json(ms_res(INVALID_CODE, false));
            }
        }
        Err(err) => {
            eprintln!("Error verifying code: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    }
   
    match update_user_bool(&db, &collection_user, id_user, "mail_verified", true).await {
        Ok(update_result) => {
            if update_result.matched_count == 0 {
                eprintln!("No matching document found to update.");
                return HttpResponse::InternalServerError()
                    .json(ms_res(NOTIN, false));
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    }
    
    MAIL_MAP.remove(&id_user);

    let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
        Ok(message_coll) => message_coll,
        Err(_) => {
            eprintln!("User message collection must be set");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };

    if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Activation".to_string(), "Félicitations! Votre Email est valide.".to_string()).await {
        eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
    }

    HttpResponse::Ok()
    .content_type("application/json")
    .json(ms_res("/twofacreation", true))
}


pub async fn twofacreation (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;

    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let app_name = match env::var("APP_NAME") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("APP_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_SENSITIVE_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    
    if !user.mail_verified {
        return HttpResponse::Ok().json(ms_res("/activation_compte", false));
    }
    if user.twofa_validated {
        return HttpResponse::Ok().json(ms_res("/twofavalidation", false));
    }
    let auth = GoogleAuthenticator::new();
    let secret = auth.create_secret(32);
    println!("secret:{}",secret);
    
    let (ciphertext, nonce) = match encryption(&secret,"TOTP_KEY") {
        Ok(result) => result,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };

    if let Err(err) = update_field_document(&db, &collection_user_sensitive, id_user, "twofa_secret", &ciphertext).await {
        eprintln!("Failed to update twofa_secret: {}", err);
        return HttpResponse::InternalServerError()
            .json(ms_res(INTERNALSERVERERROR, false));
    }
    if let Err(err) = update_field_document(&db, &collection_user_sensitive, id_user, "twofa_nonce", &nonce).await {
        eprintln!("Failed to update twofa_nonce: {}", err);
        return HttpResponse::InternalServerError()
            .json(ms_res(INTERNALSERVERERROR ,false));
    }
    let url_qr = auth.qr_code_url(&secret, &app_name, "2FA Authentication", 200, 200, ErrorCorrectionLevel::High);
    println!("url:{}",url_qr);

    let data =  json!({
        "nom": user.first_name,
        "prenom": user.last_name,
    });

    HttpResponse::Ok()
    .content_type("application/json")
    .json(fa_res_with_data(&data, true,url_qr,secret))

}
pub async fn twofavalidate (data: web::Json<TwoFaData>,user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_SENSITIVE_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let signin_log_c = match env::var("COLLECTION_USER_SIGNINLOG") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_state_c = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_s_result: Result<UserSensitive, String> = fetch_document(&db, &collection_user_sensitive, id_user).await;
    let user_s = match user_s_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let secret_str = match decryption(user_s.twofa_secret, user_s.twofa_nonce,"TOTP_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    
 
    let service = Service::IpApi;
    let ip = &data.ip;
    let country = match Locator::get(ip, service).await {
        Ok(ip_info) => ip_info.country.to_string(),
        Err(error) => {
            println!("Error: {}", error);
            "Unknown".to_string()
        }
    };
    let token_duration_env: i64 = match env::var("TOKEN_DURATION_AOTP") {
        Ok(duration) => match duration.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                eprintln!("Failed to parse TOKEN_DURATION");
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            },
        },
        Err(_) => {
            eprintln!("TOKEN_DURATION must be set");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let now: DateTime<Utc> = Utc::now();
    let moscow: Tz = "Europe/Moscow".parse().unwrap();
    let moscow_time = now.with_timezone(&moscow);
    let formatted_date = moscow_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let expires_at_moscow = moscow_time + Duration::seconds(token_duration_env);
    let expires_at_millis = expires_at_moscow.timestamp_millis();
    let expires_at_bson = BsonDateTime::from_millis(expires_at_millis);

    let log_state = LogState {
        id_user:user.id_user,
        expires_at: Some(expires_at_bson),
    };
    let signing_log = SigninLog {
        id_user:user.id_user,
        ip:data.ip.clone(),
        device: data.device.clone(),
        browser:data.browser.clone(),
        country:country.clone(),
        login_time:formatted_date.clone(),
    };
    let cookie = match generate_cookie("TOKEN_DURATION_AOTP", "APP_NAME", "TOKEN_SECRET", user.id_user) {
        Ok(cookie) => cookie,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
   // Verify the code using the helper function
   if verify_totp_code(&secret_str, &data.code) {
    if !user.twofa_validated {
    match update_user_bool(&db, &collection_user, user_s.id_user, "twofa_validated", true).await {
        Ok(update_result) => {
            if update_result.matched_count == 0 {
                eprintln!("No matching document found to update.");
                return HttpResponse::InternalServerError()
                    .json(ms_res(NOTIN, false));
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    }
}
if let Err(err) = insert_document_collection(&db, &signin_log_c, &signing_log).await {
    eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
    return HttpResponse::InternalServerError()
        .json(ms_res(INTERNALSERVERERROR, false));
}

// Insert a document into the log state collection
if let Err(err) = insert_document_collection(&db, &log_state_c, &log_state).await {
    eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
    return HttpResponse::InternalServerError()
        .json(ms_res(INTERNALSERVERERROR, false));
}

let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
    Ok(message_coll) => message_coll,
    Err(_) => {
        eprintln!("User message collection must be set");
        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
    },
};

if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Connexion".to_string(), format!("Vous êtes connectés à {} en utilisant {} {}.",country.clone(), data.device,data.browser)).await {
    eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
    return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
}

    HttpResponse::Ok()
        .append_header((SET_COOKIE, cookie))
        .content_type("application/json")
        .json(ms_res("/tsena", true))

} else {
    HttpResponse::BadRequest()
        .content_type("application/json")
        .json(ms_res("Code invalide.", false))
}
    
}
pub async fn twofavalidatestartup (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
    match log_result {
        Ok(_) => {
            return HttpResponse::Unauthorized().json(ms_res(ALREADY_LOGGED, false));
        }
        Err(_) => {
            //user is still not logged, continue code
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let data =  json!({
        "nom": user.first_name,
        "prenom": user.last_name,
    });
    HttpResponse::Ok()
    .content_type("application/json")
    .json(ms_res_with_data(&data, true,"Welcome".to_string()))
}

pub async fn check_session (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    
   
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
    match log_result {
        Ok(_log) => {
            // Document exists
            let data = json!({
                "nom": user.first_name,
                "prenom": user.last_name,
                "is_banned":user.banned,
                "id":id_user.to_string(),
            });
            println!("{}",user.banned);
            if !user.mail_verified {
                return HttpResponse::Ok()
            .content_type("application/json")
            .json(ms_res_with_data(&data, true, "/activation_compte".to_string()))
            }
        
            if !user.twofa_validated {
                return HttpResponse::Ok() 
                .content_type("application/json")
                .json(ms_res_with_data(&data, true, "/twofacreation".to_string()))
            }
            HttpResponse::Ok()
                .content_type("application/json")
                .json(ms_res_with_data(&data, true, "/tsena".to_string()))
        }
        Err(err) => {
            // Document does not exist
            let data = json!({
                "nom": user.first_name,
                "prenom": user.last_name,
                "is_banned":user.banned,
                "id":id_user.to_string(),
            });
            println!("{}",user.banned);
            if !user.mail_verified {
                return HttpResponse::Ok()
            .content_type("application/json")
            .json(ms_res_with_data(&data, true, "/activation_compte".to_string()))
            }
        
            if !user.twofa_validated {
                return HttpResponse::Ok() 
                .content_type("application/json")
                .json(ms_res_with_data(&data, true, "/twofacreation".to_string()))
            }
            HttpResponse::Ok()
                .content_type("application/json")
                .json(ms_res_with_data(&data, true, "/twofavalidation".to_string()))
        }
    }
}
pub async fn signin (data: web::Json<SigninData>,user_db: web::Data<UserDb>) -> impl Responder {
    let db: &Database = &user_db.db;

    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_SENSITIVE_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };

    let user_result: Result<User, String> = fetch_document_string(&db, &collection_user, &data.email).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(SIGNIN_FAILED, false));
        }
    };

    let user_s_result: Result<UserSensitive, String> = fetch_document(&db, &collection_user_sensitive, user.id_user).await;
    let user_s = match user_s_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };

    let hashed_password = match decryption(user_s.crypt_password, user_s.password_nonce,"PASS_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    
    match verify(&data.password, &hashed_password) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::BadRequest().json(ms_res(SIGNIN_FAILED, false));
            }
        }
        Err(err) => {
            eprintln!("Error verifying code: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    }
    let cookie = match generate_cookie("TOKEN_DURATION_BOTP", "APP_NAME", "TOKEN_SECRET", user.id_user) {
        Ok(cookie) => cookie,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };

    if !user.mail_verified {
        return HttpResponse::Ok()
    .append_header((SET_COOKIE, cookie))
    .content_type("application/json")
    .json(ms_res("/activation_compte", true))
    }

    if !user.twofa_validated {
        return HttpResponse::Ok()
        .append_header((SET_COOKIE, cookie))
        .content_type("application/json")
        .json(ms_res("/twofacreation", true))
    }

    HttpResponse::Ok()
    .append_header((SET_COOKIE, cookie))
    .content_type("application/json")
    .json(ms_res("/twofavalidation", true))
}

pub async fn logout (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
   

    let cookie = match generate_cookie_del("APP_NAME") {
        Ok(cookie) => cookie,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };

    match delete_id("COLLECTION_USER_LOGSTATE", &db, id_user).await {
        Ok(_) => HttpResponse::Ok()
            .append_header(("Set-Cookie", cookie))
            .content_type("application/json")
            .json(ms_res("/signin", true)),
        Err(error) => match error.as_str() {
            "Vous êtes déjà déconnecté." => HttpResponse::Ok()
            .append_header(("Set-Cookie", cookie))
            .content_type("application/json")
            .json(ms_res("/signin", false)),
            _ => HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false)),
        }
    }

    
}

pub async fn webcontent (data: web::Json<TitleRequest>,comp_db: web::Data<CompanyDb>) -> impl Responder {
    let db: &Database = &comp_db.db;
    let collection_content = match env::var("COLLECTION_CONTENT") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    println!("{}",data.title);
    let content_result: Result<WebContent, String> = fetch_content(&db, &collection_content, &data.title).await;
    let content = match content_result {
    Ok(content) => content,
       
     // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .json(content)


}
pub async fn news (comp_db: web::Data<CompanyDb>) -> impl Responder {
    let db: &Database = &comp_db.db;
    let collection_news = match env::var("COLLECTION_NEWS") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NEWS_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
   

    match fetch_all_documents::<News>(db, &collection_news).await {
        Ok(mut news_items) => {
            let format = "%d %B %Y %H:%M"; // Example format "12 Août 2024 13:16"

            news_items.iter_mut().for_each(|news_item| {
                // Convert BSON DateTime to milliseconds since epoch
                let bson_date = news_item.date.clone();
                let millis = bson_date.timestamp_millis();
                
                // Convert milliseconds to seconds and nanoseconds
                let seconds = (millis / 1000) as i64;
                let nanoseconds = ((millis % 1000) * 1_000_000) as u32;
                
                // Convert to Chrono DateTime
                let chrono_date = DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(seconds, nanoseconds),
                    Utc
                );

                // Format the date to the desired format
                let mut formatted_date = chrono_date.format(format).to_string();
                let parts: Vec<&str> = formatted_date.split(' ').collect();
                if parts.len() > 2 {
                    let month = parts[1];
                    formatted_date = formatted_date.replace(month, month_to_french(month));
                }

                println!("{}", formatted_date);

                news_item.date_str = Some(formatted_date);
            });

            // Sort news_items by date in descending order
            news_items.sort_by(|a, b| b.date.cmp(&a.date));

            let newest_news_items = news_items.into_iter().take(20).collect::<Vec<_>>();

            HttpResponse::Ok()
                .content_type("application/json")
                .json(newest_news_items)
        },
        Err(err) => {
            eprintln!("Failed to fetch documents: {}", err);
            HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false))
        }
    }

}
pub async fn status (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let data = json!({
        "active": user.active,
        "twofa_validated": user.twofa_validated,
        "verified":user.verified,
        "mail_verified":user.mail_verified,
        "banned":user.banned,
        "kyc_verified":user.kyc_verified,
        
    });
    HttpResponse::Ok()
    .content_type("application/json")
    .json(ms_res_json(&data,true))
}
pub async fn profile (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };

    let inscrit_le_formatted = match DateTime::parse_from_rfc3339(&user.created_at) {
        Ok(dt) => {
            // Convert to local time zone and format
            dt.with_timezone(&Local).format("%d %B %Y %H:%M").to_string()
        }
        Err(_) => user.created_at.clone(),
    };

    let data = json!({
        "nom": user.first_name,
        "prenom": user.last_name,
        "sexe":user.gender,
        "date_naissance":user.date_naissance,
        "email":user.email,
        "pays":user.pays,
        "addresse":user.addresse,
        "region":user.region,
        "ville":user.ville,
        "mobile":user.mobile,
        "appareil_inscription":user.registration_device,
        "navigateur_inscription":user.registration_browser,
        "inscrit_le":inscrit_le_formatted,

    });
    HttpResponse::Ok()
    .content_type("application/json")
    .json(ms_res_json(&data,true))
}
pub async fn profile_update (data: web::Json<ProfileData>,user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let mut user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };

    user.first_name=data.nom.clone();
    user.last_name=data.prenom.clone();
    user.gender=data.sexe.clone();
    user.date_naissance=data.date_naissance.clone();
    user.email=data.email.clone();
    user.pays=data.pays.clone();
    user.addresse=data.addresse.clone();
    user.region=data.region.clone();
    user.ville=data.ville.clone();
    user.mobile=data.mobile;
    user.registration_device=data.appareil_inscription.clone();
    user.registration_browser=data.navigateur_inscription.clone();
    user.created_at=data.inscrit_le.clone();

    match overwrite_document_collection(&db, &collection_user, &user,id_user).await {
        Ok(_) => {

            let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
                Ok(message_coll) => message_coll,
                Err(_) => {
                    eprintln!("User message collection must be set");
                    return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
                },
            };
            
            if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Information du Profil".to_string(), "Vos informations de profil a été mise à jour.".to_string() ).await {
                eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            }
           
            HttpResponse::Ok().finish()
                
               
        },
        Err(err) => {
            eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
            HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR ,false))
        },
    }
   
}
pub async fn security (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    HttpResponse::Ok()
    .content_type("application/json")
    .json("news_items")
}

pub async fn otp_renew (data: web::Json<OTPNewData>,user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;

    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_SENSITIVE_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let app_name = match env::var("APP_NAME") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("APP_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let user_s_result: Result<UserSensitive, String> = fetch_document(&db, &collection_user_sensitive, user.id_user).await;
    let user_s = match user_s_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    
    let hashed_password = match decryption(user_s.crypt_password, user_s.password_nonce,"PASS_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let secret_str = match decryption(user_s.twofa_secret, user_s.twofa_nonce,"TOTP_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    match verify(&data.password, &hashed_password) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::BadRequest().json(ms_res( OTP_NEW_ERROR, false));
            }
            if verify_totp_code(&secret_str, &data.actual_code) {
                let auth = GoogleAuthenticator::new();
                let secret = auth.create_secret(32);
               
                
                let (ciphertext, nonce) = match encryption(&secret,"TOTP_KEY") {
                    Ok(result) => result,
                    Err(err) => {
                        eprintln!("{}", err);
                        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
                    }
                };
                match update_user_bool(&db, &collection_user, user_s.id_user, "twofa_validated", false).await {
                    Ok(update_result) => {
                        if update_result.matched_count == 0 {
                            eprintln!("No matching document found to update.");
                            return HttpResponse::InternalServerError()
                                .json(ms_res(NOTIN, false));
                        }
                    }
                    Err(err) => {
                        eprintln!("{}", err);
                        return HttpResponse::InternalServerError()
                            .json(ms_res(INTERNALSERVERERROR, false));
                    }
                }

                if let Err(err) = update_field_document(&db, &collection_user_sensitive, id_user, "twofa_secret", &ciphertext).await {
                    eprintln!("Failed to update twofa_secret: {}", err);
                    return HttpResponse::InternalServerError()
                        .json(ms_res(INTERNALSERVERERROR, false));
                }
                if let Err(err) = update_field_document(&db, &collection_user_sensitive, id_user, "twofa_nonce", &nonce).await {
                    eprintln!("Failed to update twofa_nonce: {}", err);
                    return HttpResponse::InternalServerError()
                        .json(ms_res(INTERNALSERVERERROR ,false));
                }
                let url_qr = auth.qr_code_url(&secret, &app_name, "2FA Authentication", 200, 200, ErrorCorrectionLevel::High);
                println!("url:{}",url_qr);

                let data =  json!({
                    "nom": user.first_name,
                    "prenom": user.last_name,
                });
                
                HttpResponse::Ok()
                .content_type("application/json")
                .json(fa_res_with_data(&data, true,url_qr,secret))
                        
            }   else {
                HttpResponse::BadRequest()
                    .content_type("application/json")
                    .json(ms_res( OTP_NEW_ERROR, false))
            }
        }
        Err(err) => {
            eprintln!("Error verifying code: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    }
    
    
    
}
pub async fn otp_renew_validate (data: web::Json<OTPNewDataValidate>,user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_SENSITIVE_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
   
    let user_s_result: Result<UserSensitive, String> = fetch_document(&db, &collection_user_sensitive, id_user).await;
    let user_s = match user_s_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let secret_str = match decryption(user_s.twofa_secret, user_s.twofa_nonce,"TOTP_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    
   // Verify the code using the helper function
   if verify_totp_code(&secret_str, &data.new_code) {
    if !user.twofa_validated {
    match update_user_bool(&db, &collection_user, user_s.id_user, "twofa_validated", true).await {
        Ok(update_result) => {
            if update_result.matched_count == 0 {
                eprintln!("No matching document found to update.");
                return HttpResponse::InternalServerError()
                    .json(ms_res(NOTIN, false));
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    }
}

let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
    Ok(message_coll) => message_coll,
    Err(_) => {
        eprintln!("User message collection must be set");
        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
    },
};

if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Renouvelement code OTP".to_string(), "Votre code OTP a été renouvelé avec succès.".to_string() ).await {
    eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
    return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
}

    HttpResponse::Ok()
        .content_type("application/json")
        .json(ms_res("OTP renouvelé avec succès ", true))

} else {
    HttpResponse::BadRequest()
        .content_type("application/json")
        .json(ms_res("Code invalide.", false))
}
}

pub async fn newpass (data: web::Json<NewPassData>,user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;

    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_SENSITIVE_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let app_name = match env::var("APP_NAME") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("APP_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    let user_s_result: Result<UserSensitive, String> = fetch_document(&db, &collection_user_sensitive, user.id_user).await;
    let user_s = match user_s_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };
    
    let hashed_password = match decryption(user_s.crypt_password, user_s.password_nonce,"PASS_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let secret_str = match decryption(user_s.twofa_secret, user_s.twofa_nonce,"TOTP_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    match verify(&data.actual_password, &hashed_password) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::BadRequest().json(ms_res( OTP_NEW_ERROR, false));
            }
            if &data.actual_password == &data.new_password
            {
                return HttpResponse::BadRequest().json(ms_res( SAME_PASS_ERROR, false));
            }
            if verify_totp_code(&secret_str, &data.code) {

                let hashed_password = match hash(&data.new_password, DEFAULT_COST) {
                    Ok(hash) => hash,
                    Err(err) => {
                        eprintln!("Failed to hash password: {}", err);
                        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
                    },
                };
                let (cryptpass, pass_nonce) = match encryption(&hashed_password,"PASS_KEY") {
                    Ok(result) => result,
                    Err(err) => {
                        eprintln!("{}", err);
                        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
                    }
                };
 
                if let Err(err) = update_field_document(&db, &collection_user_sensitive, id_user, "crypt_password", &cryptpass).await {
                    eprintln!("Failed to update encrypted password: {}", err);
                    return HttpResponse::InternalServerError()
                    .json(ms_res(INTERNALSERVERERROR, false));
                }
                if let Err(err) = update_field_document(&db, &collection_user_sensitive, id_user, "password_nonce", &pass_nonce).await {
                    eprintln!("Failed to update password nonce: {}", err);
                    return HttpResponse::InternalServerError()
                    .json(ms_res(INTERNALSERVERERROR, false));
                }

                let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
                    Ok(message_coll) => message_coll,
                    Err(_) => {
                        eprintln!("User message collection must be set");
                        return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
                    },
                };
                
                if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Renouvèlement Mot de passe".to_string(), "Votre mot de passe a été renouvelé avec succès.".to_string() ).await {
                    eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
                    return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
                }
 
                HttpResponse::Ok()
                .content_type("application/json")
                .json(ms_res("Mot de passe renouvelé avec succès", true))
                        
            }   else {
                HttpResponse::BadRequest()
                    .content_type("application/json")
                    .json(ms_res( OTP_NEW_ERROR, false))
            }
        }
        Err(err) => {
            eprintln!("Error verifying code: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    }
    
    
}

pub async fn kyc (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };


    let data = json!({
       "cin_number":user.cin_number,
       "cin_issued":user.cin_issued,
       "cin_photo_recto_url":user.cin_photo_recto_url,
       "cin_photo_verso_url":user.cin_photo_verso_url,
       "address_photo_url":user.address_photo_url,
       "photo_url":user.photo_url,
       

    });
    HttpResponse::Ok()
    .content_type("application/json")
    .json(ms_res_json(&data,true))
}

pub async fn sendimage (mut payload: Multipart,req: actix_web::HttpRequest) -> impl Responder {
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
   
    let upload_dir = "./uploads";
    if let Err(e) = create_dir_all(upload_dir) {
        eprintln!("Error creating uploads directory: {:?}", e);
        return HttpResponse::InternalServerError().finish();
    }

    while let Some(item) = payload.next().await {
        let mut field = item.unwrap();

        // Generate a random ID for the file
        let random_id = Uuid::new_v4().to_string();

        let mut id_parts: Vec<String> = random_id.split('-').map(|s| s.to_string()).collect();
        if id_parts.len() == 5 {
            id_parts[4] = id_user.to_string();
        }
        let custom_id = id_parts.join("-");
        
        // Extract file extension from the MIME type
        let mime_type = field.headers().get("content-type")
            .and_then(|hd| hd.to_str().ok())
            .unwrap_or("application/octet-stream"); // Default MIME type if not found
        let file_ext = match mime_type {
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/gif" => "gif",
            "image/webp" => "webp",
            _ => "unknown", // Fallback for other MIME types
        };

        // Create the file path
        let file_path = format!("{}/{}.{}", upload_dir, custom_id, file_ext);

        // Save the file to disk
        let mut file = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Error creating file: {:?}", e);
                return HttpResponse::InternalServerError().finish();
            }
        };

        while let Some(chunk) = field.next().await {
            let data = match chunk {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error reading chunk: {:?}", e);
                    return HttpResponse::InternalServerError().finish();
                }
            };

            if let Err(e) = file.write_all(&data) {
                eprintln!("Error writing to file: {:?}", e);
                return HttpResponse::InternalServerError().finish();
            }
        }

        // Return the random ID as the response
        return HttpResponse::Ok().json(json!({ "id": custom_id }));
    }

    HttpResponse::InternalServerError().finish()
}

pub async fn kyc_update (data: web::Json<KYCData>,user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    println!("{:?}",data);
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_result: Result<User, String> = fetch_document(&db, &collection_user, id_user).await;
    let mut user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(&err, false));
        }
    };

    user.cin_number=data.cin_number.clone();
    user.cin_issued=data.cin_issued.clone();
    user.cin_photo_recto_url=data.cin_photo_recto_url.clone();
    user.cin_photo_verso_url=data.cin_photo_verso_url.clone();
    user.address_photo_url=data.address_photo_url.clone();
    user.photo_url=data.photo_url.clone();
    

    match overwrite_document_collection(&db, &collection_user, &user,id_user).await {
        Ok(_) => {

            let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
                Ok(message_coll) => message_coll,
                Err(_) => {
                    eprintln!("User message collection must be set");
                    return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
                },
            };
            
            if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Mise à jour du KYC".to_string(), "Vos informations de KYC a été mise à jour.".to_string() ).await {
                eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            }
           
            HttpResponse::Ok().finish()
                
               
        },
        Err(err) => {
            eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
            HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR ,false))
        },
    }
   
}

pub async fn pass_recovery (data: web::Json<RecoveryData>,user_db: web::Data<UserDb>) -> impl Responder {
    let db: &Database = &user_db.db;
    
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };

    let user_result: Result<User, String> = fetch_document_string(&db, &collection_user, &data.email_recovery).await;
    let user = match user_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(NOTIN, false));
        }
    };

    let user_s_result: Result<UserSensitive, String> = fetch_document(&db, &collection_user_sensitive, user.id_user).await;
    let user_s = match user_s_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(NOTIN, false));
        }
    };
    let hashed_secret = match decryption(user_s.secret_word_crypt, user_s.secret_word_nonce,"SECRET_WORD_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    
    match verify(&data.secret_word, &hashed_secret) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::BadRequest().json(ms_res(PASS_RECOVERY_ERROR, false));
            }
        }
        Err(err) => {
            eprintln!("Error verifying code: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    }

    let secret_str = match decryption(user_s.twofa_secret, user_s.twofa_nonce,"TOTP_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };

    if verify_totp_code(&secret_str, &data.otp_code) {

        let hashed_password = match hash(&data.password_recovery, DEFAULT_COST) {
            Ok(hash) => hash,
            Err(err) => {
                eprintln!("Failed to hash password: {}", err);
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            },
        };
        let (cryptpass, pass_nonce) = match encryption(&hashed_password,"PASS_KEY") {
            Ok(result) => result,
            Err(err) => {
                eprintln!("{}", err);
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            }
        };

        if let Err(err) = update_field_document(&db, &collection_user_sensitive, user_s.id_user, "crypt_password", &cryptpass).await {
            eprintln!("Failed to update encrypted password: {}", err);
            return HttpResponse::InternalServerError()
            .json(ms_res(INTERNALSERVERERROR, false));
        }
        if let Err(err) = update_field_document(&db, &collection_user_sensitive, user_s.id_user, "password_nonce", &pass_nonce).await {
            eprintln!("Failed to update password nonce: {}", err);
            return HttpResponse::InternalServerError()
            .json(ms_res(INTERNALSERVERERROR, false));
        }

        let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
            Ok(message_coll) => message_coll,
            Err(_) => {
                eprintln!("User message collection must be set");
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            },
        };
        
        if let Err(err) = insert_user_message(&db, &usermessage_coll, user.id_user, "Récuperation Mot de passe".to_string(), "Votre mot de passe a été renouvelé avec succès.".to_string() ).await {
            eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }

        HttpResponse::Ok()
        .content_type("application/json")
        .json(ms_res("Mot de passe renouvelé avec succès", true))

    } else {
        HttpResponse::BadRequest()
            .content_type("application/json")
            .json(ms_res( PASS_RECOVERY_ERROR, false))
    }

   
}

pub async fn user_message (user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {

    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_log = match env::var("COLLECTION_USER_LOGSTATE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let log_result: Result<LogState, String> = fetch_document(&db, &collection_log, id_user).await;
        match log_result {
            Ok(_log) => {
             
            }
            Err(_err) => {
               
                return HttpResponse::Unauthorized().json(ms_res("/twofavalidation", false));
            }
        }
    let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
        Ok(message_coll) => message_coll,
        Err(_) => {
            eprintln!("User message collection must be set");
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        },
    };

    match fetch_all_documents_by_user::<UserMessage>(db, &usermessage_coll, id_user).await {
        Ok(mut user_message) => {
            let format = "%d %B %Y %H:%M"; // Example format "12 Août 2024 13:16"

            user_message.iter_mut().for_each(|user_message| {
                // Convert BSON DateTime to milliseconds since epoch
                let bson_date = user_message.date.clone();
                let millis = bson_date.timestamp_millis();
                
                // Convert milliseconds to seconds and nanoseconds
                let seconds = (millis / 1000) as i64;
                let nanoseconds = ((millis % 1000) * 1_000_000) as u32;
                
                // Convert to Chrono DateTime
                let chrono_date = DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(seconds, nanoseconds),
                    Utc
                );

                let chrono_date = match chrono_date.checked_add_signed(chrono::Duration::hours(3)) {
                    Some(new_date) => new_date,
                    None => {
                        eprintln!("Error: Failed to add 3 hours to the date.");
                        chrono_date // Fallback to the original date if the addition fails
                    }
                };

                // Format the date to the desired format
                let mut formatted_date = chrono_date.format(format).to_string();
                let parts: Vec<&str> = formatted_date.split(' ').collect();
                if parts.len() > 2 {
                    let month = parts[1];
                    formatted_date = formatted_date.replace(month, month_to_french(month));
                }

                user_message.date_str = Some(formatted_date);
            });

            // Sort news_items by date in descending order
            user_message.sort_by(|a, b| b.date.cmp(&a.date));

            HttpResponse::Ok()
                .content_type("application/json")
                .json(user_message)
        },
        Err(err) => {
            eprintln!("Failed to fetch documents: {}", err);
            HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false))
        }
    }

}

pub async fn otp_recovery (data: web::Json<OtpRecoveryData>,user_db: web::Data<UserDb>,req: actix_web::HttpRequest) -> impl Responder {
    let db: &Database = &user_db.db;
    let id_user = match decode_token(&req) {
        Some(id) => id,
        None => {
            println!("cookie vide or token decode error");
            return HttpResponse::Unauthorized().json(ms_res(EXPIRED, false));
        }
    };
    let collection_user_sensitive = match env::var("COLLECTION_USER_SENSITIVE") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_SENSITIVE_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let collection_user = match env::var("COLLECTION_USER") {
        Ok(name) => name,
        Err(err) => {
            eprintln!("COLLECTION_NAME_ERROR: {}", err);
            return HttpResponse::InternalServerError()
                .json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    let user_s_result: Result<UserSensitive, String> = fetch_document(&db, &collection_user_sensitive,id_user).await;
    let user_s = match user_s_result {
    Ok(user) => user, // Extract the user if the result is Ok
    Err(err) => {
        eprintln!("{}", err);
        return HttpResponse::NotFound().json(ms_res(NOTIN, false));
        }
    };
    let hashed_secret = match decryption(user_s.secret_word_crypt, user_s.secret_word_nonce,"SECRET_WORD_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    
    match verify(&data.familymember, &hashed_secret) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::BadRequest().json(ms_res(OTP_RECOVERY_ERROR, false));
            }
        }
        Err(err) => {
            eprintln!("Error verifying code: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    }
    let hashed_password = match decryption(user_s.crypt_password, user_s.password_nonce,"PASS_KEY") {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("{}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
    };
    match verify(&data.password, &hashed_password) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::BadRequest().json(ms_res( OTP_RECOVERY_ERROR, false));
            }
            
        }
            Err(err) => {
                eprintln!("Error verifying code: {}", err);
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            }
        }

       
        match update_user_bool(&db, &collection_user, id_user, "twofa_validated", false).await {
            Ok(update_result) => {
                if update_result.matched_count == 0 {
                    eprintln!("No matching document found to update.");
                    return HttpResponse::InternalServerError()
                        .json(ms_res(NOTIN, false));
                }
            }
            Err(err) => {
                eprintln!("{}", err);
                return HttpResponse::InternalServerError()
                    .json(ms_res(INTERNALSERVERERROR, false));
            }
        }
        let cookie = match generate_cookie_del("APP_NAME") {
            Ok(cookie) => cookie,
            Err(err) => {
                eprintln!("{}", err);
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            }
        };
        let usermessage_coll = match env::var("COLLECTION_USER_MESSAGE") {
            Ok(message_coll) => message_coll,
            Err(_) => {
                eprintln!("User message collection must be set");
                return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
            },
        };
        
        if let Err(err) = insert_user_message(&db, &usermessage_coll, id_user, "Récuperation code OTP".to_string(), "Une demande de réinitialisation du code OTP a été reçue.".to_string() ).await {
            eprintln!("DATABASE_INSERTION_FAILURE: {}", err);
            return HttpResponse::InternalServerError().json(ms_res(INTERNALSERVERERROR, false));
        }
        HttpResponse::Ok()
        .append_header(("Set-Cookie", cookie))
        .content_type("application/json")
        .json(ms_res("/signin", true))
}