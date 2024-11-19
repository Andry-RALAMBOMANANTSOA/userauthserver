//use dashmap::DashMap;
use timedmap::TimedMap;
use std::sync::Arc;
use crate::structs::*;
use lazy_static::lazy_static;
use dashmap::DashMap;
use hmac::Hmac;
use sha2::Sha256;

     lazy_static! {
        //pub static ref TOKEN_MAP: Arc<TokenMap> = Arc::new(TimedMap::new());
        pub static ref MAIL_MAP: Arc<MailMap> = Arc::new(TimedMap::new());
        //pub static ref PHONE_MAP: Arc<PhoneMap> = Arc::new(DashMap::new());
        
    }
    
    pub type WsConnections = Arc<DashMap<String, actix_ws::Session>>;
    pub type UserMessageMap = Arc<DashMap<i64, usize>>;//id_user is the key, value is message count incremented
    pub type UserMessageSessions = Arc<DashMap<i64, Vec<String>>>;//id_user is the key, value is array of session ID
    pub type UserMessageSessionsInv = Arc<DashMap<String, i64>>;//session ID is the key, value is id_user
   