use serde::{Deserialize, Serialize};
use std::default::Default;
//use dashmap::DashMap;
use timedmap::TimedMap;
use mongodb::bson::DateTime as BsonDateTime;
use mongodb::bson::oid::ObjectId;
use std::fmt;


#[derive(Clone)]
pub struct UserDb {
    pub db: mongodb::Database,
}

#[derive(Clone)]
pub struct CompanyDb {
    pub db: mongodb::Database,
}

#[derive(Deserialize,Debug)]
pub struct SignupData {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub mobile:String,
    pub password: String,
    pub secret_word: String,
    pub ip:String,
    pub device: String,
    pub browser:String,  // Device used for registration, e.g., "web", "android", "ios" etc.  // Set default to "web" as it's the most common device used for registration.  // Set default date for created_at and updated_at fields.  // Add new fields for google_auth_secret and verified fields.  // Add new field for mail_verified fields.  // Add new field for device_token, last_login
}

#[derive(Deserialize,Debug)]
pub struct SigninData {
    pub email: String,
    pub password: String,
     
}
#[derive(Deserialize,Debug)]
pub struct OtpRecoveryData {
    pub familymember: String,
    pub password: String,
     
}
#[derive(Deserialize,Debug)]
pub struct RecoveryData {
    pub email_recovery: String,
    pub secret_word: String,
    pub otp_code:String,
    pub password_recovery:String,
     
}
#[derive(Deserialize,Debug)]
pub struct OTPNewData {
    pub actual_code: String,
    pub password: String,
     
}
#[derive(Deserialize,Debug)]
pub struct NewPassData {
    pub code: String,
    pub actual_password: String,
    pub new_password:String,
     
}
#[derive(Deserialize,Debug)]
pub struct OTPNewDataValidate {
    pub new_code: String,
    
     
}
#[derive(Deserialize,Debug)]
pub struct PassNewData {
    pub otp_code: String,
    pub password: String,
    pub new_password:String,
     
}
#[derive(Deserialize,Debug)]
pub struct ProfileData {
    pub nom: String,
    pub prenom: String,
    pub sexe: String,
    pub date_naissance:String,
    pub email: String,
    pub pays:String,
    pub addresse: String,
    pub region:String,
    pub ville:String,
    pub mobile: i32,
    pub appareil_inscription: String,
    pub navigateur_inscription:String,  // Device used for registration, e.g., "web", "android", "ios" etc.  // Set default to "web" as it's the most common device used for registration.  // Set default date for created_at and updated_at fields.  // Set default to false for verified and mail_verified fields.  // Add new fields for google_auth_secret and verified fields.  // Add new field for mail_
    pub inscrit_le: String, 
}
#[derive(Deserialize,Debug)]
pub struct KYCData {
    pub cin_number: String,
    pub cin_issued: String,
    pub cin_photo_recto_url: String,
    pub cin_photo_verso_url:String,
    pub address_photo_url: String,
    pub photo_url:String,
   
}
#[derive(Deserialize,Debug,Serialize)]
pub struct SigninLog {
    pub id_user:i64,
    pub ip:String,
    pub device: String,
    pub browser:String,
    pub country:String,
    pub login_time:String, 
}
#[derive(Deserialize,Debug,Serialize)]
pub struct LogState {
    pub id_user:i64,
    pub expires_at: Option<BsonDateTime>,  
}
#[derive(Deserialize,Debug)]
pub struct EmailValidationData {
    pub code:String,
}
#[derive(Deserialize,Debug)]
pub struct TwoFaData {
    pub code:String,
    pub ip:String,
    pub device: String,
    pub browser:String,  // Device used for registration, e.g., "web", "android", "ios" etc.  // Set default to "web" as it's the most common device used for registration.  // Set default date for created_at and updated_at fields.  // Add new fields for google_auth_secret and verified fields.  // Add new field for mail_verified fields.  // Add new field for device
}

#[derive(Serialize)]
pub struct MSResponse {
    pub message: String,
    pub success: bool,
}
#[derive(Serialize)]
pub struct MSResponseData {
    pub message: String,
    pub success: bool,
    pub data: serde_json::Value,
    
}
#[derive(Serialize)]
pub struct MSResponseJson {
    pub success: bool,
    pub data: serde_json::Value,
    
}
#[derive(Serialize)]
pub struct FAResponseData {
    pub qrurl: String,
    pub qrsecret: String,
    pub success: bool,
    pub data: serde_json::Value,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct News {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub date: BsonDateTime, 
    pub title: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_str: Option<String>,
}


#[derive(Serialize,Deserialize,Debug)]
pub struct User {
    pub first_name: String,
    pub last_name: String,
    pub gender: String,
    pub date_naissance:String,
    pub email: String,
    pub id_user:i64,
    pub pays:String,
    pub addresse: String,
    pub region:String,
    pub ville:String,
    pub mobile: i32,
    pub active: bool,
    pub cin_number:String,
    pub cin_issued:String,
    pub cin_photo_recto_url:String,
    pub cin_photo_verso_url:String,
    pub justification_addresse_url:String,
    pub photo_url:String,
    pub last_login: String,
    pub registration_ip: String,
    pub registration_device: String,
    pub registration_browser:String,  // Device used for registration, e.g., "web", "android", "ios" etc.  // Set default to "web" as it's the most common device used for registration.  // Set default date for created_at and updated_at fields.  // Set default to false for verified and mail_verified fields.  // Add new fields for google_auth_secret and verified fields.  // Add new field for mail_
    pub created_at: String,
    pub twofa_validated: bool,
    pub verified:bool,
    pub mail_verified:bool,
    //pub mobile_verified:bool,
    pub banned:bool,
    pub demo: bool,
    pub kyc_verified: bool,
   
    pub address_photo_url:String,
   
   
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AML {
    pub id_user: i64,
    pub occupation: String,
    pub employer: String,
    pub activity:String,
    pub source_of_funds: String, // Source of funds (e.g., salary, investment, inheritance)
    pub annual_income: String, // Annual income (could be in a specific currency format)
    pub net_worth: String, // Net worth (could be in a specific currency format)
    pub politically_exposed: bool, // Whether the user is a Politically Exposed Person (PEP)
    pub risk_assessment: String, // Low, Medium, High
    pub aml_review_date: String, // Date of last AML checks
    pub suspicious_activity_reported: bool, // Whether a Suspicious Activity Report (SAR) was filed
    pub suspicious_activity_notes: String, // Notes on any suspicious activities
   
}

#[derive(Serialize,Deserialize,Debug)]
pub struct UserSensitive {
    pub id_user:i64,
    pub crypt_password: Vec<u8>,
    pub password_nonce:Vec<u8>,
    pub twofa_secret: Vec<u8>,
    pub twofa_nonce: Vec<u8>,
    pub secret_word_crypt:Vec<u8>,
    pub secret_word_nonce: Vec<u8>,
    pub pin_crypt:Vec<u8>,
    pub pin_nonce: Vec<u8>,
            
}
impl Default for UserSensitive {
    fn default() -> Self {
        UserSensitive {
            id_user: 0,
            crypt_password: Vec::new(),
            password_nonce:Vec::new(),
            twofa_secret: Vec::new(),
            twofa_nonce: Vec::new(),
            secret_word_crypt: Vec::new(),
            secret_word_nonce: Vec::new(),
            pin_crypt: Vec::new(),
            pin_nonce: Vec::new(),
        }
    }
}
    
impl Default for User {
    fn default() -> Self {
        User {
            first_name: String::new(),
            last_name: String::new(),
            gender:String::new(),
            date_naissance:String::new(),
            email: String::new(),
            id_user: 0,
            pays:String::new(),
            addresse: String::new(),
            region: String::new(),
            ville: String::new(),
            mobile: 0,
            active: true,
            cin_number: String::new(),
            cin_issued: String::new(),
            cin_photo_recto_url: String::new(),
            cin_photo_verso_url: String::new(),
            justification_addresse_url: String::new(),
            photo_url: String::new(),
            last_login: String::new(),
            registration_ip: String::new(),
            registration_device:String::new(),
            registration_browser:String::new(),
            created_at:String::new(), // Set default date
            twofa_validated: false,
            verified: false, // Set default to false as user is not verified by default
            mail_verified: false, // Set default to false as user is not verified by default
            //mobile_verified:false,
            banned:false,
            demo:true,
            kyc_verified:false,
           
            address_photo_url: String::new(),
            
            
        }
    }
}

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct TokenData {
    pub id_user: i64,
    pub issued_at: String, //Human readable format
    pub exp: usize,//Human readable format
    pub nonce:String, 
    /*pub verified:bool,
    pub demo: bool,
    pub kyc_verified: bool,
    pub aml_verified: bool,
    pub mail_verified:bool,
    pub twofa_verified:bool,
    pub banned:bool,*/
}

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct MailCode{
    pub code:String,
}

pub type MailMap = TimedMap<i64, MailCode>;
//pub type PhoneMap = DashMap<i64, MobileCode>;

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct WebContent{
    pub title:String,
    pub text:String,
}

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct TitleRequest{
    pub title:String,
    
}

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct UserMessage{
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub id_user:i64,
    pub date:BsonDateTime,
    pub title:String,
    pub message:String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_str: Option<String>,
    
}

