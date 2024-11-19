use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use mongodb::Client;
use dotenv::dotenv;
use std::env;
use crate::handler::signup; // Import the signup function
use crate::shared::*;
use crate::structs::*;
use std::sync::Arc;
mod structs;
mod function;
mod string_message;
mod handler;
mod shared; // Include the shared module
use crate::handler::*;
use crate::function::*;
mod websocket;
use crate::websocket::*;
use dashmap::DashMap;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let mongo_uri = env::var("MONGO_URI").expect("MONGO_URI must be set");
    let db_user = env::var("DB_USER").expect("DB_USER must be set");
    let db_comp = env::var("DB_COMPANY").expect("DB_COMPANY must be set");

    let client = Client::with_uri_str(&mongo_uri).await.expect("Failed to initialize client");
    let db_u = client.database(&db_user);
    let db_c = client.database(&db_comp);

    let user_db = UserDb { db: db_u };
    let comp_db = CompanyDb { db: db_c.clone() };

    let ws_connections = Arc::new(DashMap::new());
    let user_message_counts = Arc::new(DashMap::new());
    let user_message_session = Arc::new(DashMap::new());
    let user_message_session_inv:UserMessageSessionsInv = Arc::new(DashMap::new());

    // Start the task to watch the MongoDB collection
    let watch_comp_db = comp_db.clone();
    let watch_ws_connections = ws_connections.clone(); // Clone for the watch task
    let collection_news = "news";
    tokio::spawn(async move {
        if let Err(err) = watch_news_collection(watch_comp_db, collection_news, watch_ws_connections).await {
            eprintln!("Error watching collection: {:?}", err);
        }
    });
    let watch_user_db = user_db.clone();
    let watch_usermess = user_message_counts.clone(); // Clone for the watch task
    let collection_umess = "usermessage";
    let watch_ws_connections_t = ws_connections.clone();
    let session_usermess = user_message_session.clone();
    tokio::spawn(async move {
        if let Err(err) = watch_user_messages(watch_user_db, collection_umess, watch_usermess,session_usermess,watch_ws_connections_t).await {
            eprintln!("Error watching collection: {:?}", err);
        }
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);
 
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(user_db.clone()))
            .app_data(web::Data::new(comp_db.clone()))
            .app_data(web::Data::new(ws_connections.clone()))
            .app_data(web::Data::new(user_message_counts.clone()))
            .app_data(web::Data::new(user_message_session.clone()))
            .app_data(web::Data::new(user_message_session_inv.clone()))
            .route("/signup", web::post().to(signup))
            .route("/signin", web::post().to(signin))
            .route("/checksession", web::get().to(check_session))
            .route("/mailcodevalidation",web::post().to(mailcodevalidation))
            .route("/activateaccount",web::get().to(activateaccount))
            .route("/twofacreation",web::get().to(twofacreation))
            .route("/twofavalidatestartup",web::get().to(twofavalidatestartup))
            .route("/twofavalidate",web::post().to(twofavalidate))
            .route("/logout",web::get().to(logout))
            .route("/webcontent",web::post().to(webcontent))
            .route("/news",web::get().to(news))
            .route("/status",web::get().to(status))
            .route("/profile",web::get().to(profile))
            .route("/security",web::get().to(security))
            .route("/kyc",web::get().to(kyc))
            
            .route("/profile_update",web::post().to(profile_update))
            .route("/otp_renew",web::post().to(otp_renew))
            .route("/otp_renew_validate",web::post().to(otp_renew_validate))
            .route("/newpass",web::post().to(newpass))
            .route("/sendimage", web::post().to(sendimage))
            .route("/kyc_update",web::post().to(kyc_update))
            .route("/pass_recovery",web::post().to(pass_recovery))
            .route("/otprecovery",web::post().to(otp_recovery))
            .route("/user_message",web::get().to(user_message))

            // WebSocket routes
       
        .route("/ws/news", web::get().to(news_handler))
        .route("/ws/usermessage", web::get().to(user_message_handler))
            
            
            
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
