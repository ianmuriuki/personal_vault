// Import necessary libraries and modules from the IC SDK and other dependencies.
// use ic_cdk::api::call::call;
use ic_cdk::pre_upgrade;
use ic_cdk::post_upgrade;
use ic_cdk::update;

use ic_cdk::export::candid::{CandidType, Encode, Decode};
use ic_cdk::storage;
// use ic_cdk::api::data_certificate;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use bcrypt::{hash, verify}; // Secure password hashing
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation}; // JWT
use aes::{Aes128, BlockEncrypt, BlockDecrypt}; // AES for encryption
use aes::block_modes::{BlockMode, Cbc}; // Block mode for AES
use aes::cipher::{KeyIvInit, block_padding::Pkcs7}; // Key/IV initialization and PKCS7 padding
use serde::{Serialize, Deserialize};
use ic_cdk::query;

// Stable memory storage
use ic_stable_structures::{memory_manager::{MemoryId, MemoryManager}, DefaultMemoryImpl}; //cell::Cell

// User data type for persistent storage
#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
struct UserData {
    users: HashMap<String, User>, // Persistent storage for users.
}

// Initialize stable memory for the canister
thread_local! {
    static MEMORY: MemoryManager<DefaultMemoryImpl> = MemoryManager::new();
}

// Struct for storing user details
#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password_hash: String,
    role: String,
    data: HashMap<String, DataEntry>,
}

// Struct for storing data entries
#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
struct DataEntry {
    value: String,
    timestamp: DateTime<Utc>,
    expiration: Option<DateTime<Utc>>,
    shared_with: Vec<String>,
}

// Struct for creating a new user
#[derive(CandidType)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: String,
}

// Struct for login requests
#[derive(CandidType)]
struct LoginRequest {
    username: String,
    password: String,
}

// Struct for login responses
#[derive(CandidType)]
struct LoginResponse {
    success: bool,
    message: String,
    token: Option<AccessToken>,
}

// Struct for access token
#[derive(CandidType)]
struct AccessToken {
    token: String,
    username: String,
}

// Struct for storing claims in JWT
#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

// Struct for storing data request
#[derive(CandidType)]
struct DataRequest {
    token: String,
    key: String,
}

// Struct for data responses
#[derive(CandidType)]
struct DataResponse {
    success: bool,
    message: String,
    data: Option<String>,
}

// --- Functions for canister management and operations ---

/// Pre-upgrade function to save user data before upgrade
#[pre_upgrade]
fn pre_upgrade() {
    MEMORY.with(|memory| {
        let users = storage::get::<HashMap<String, User>>().clone();
        memory.save(MemoryId::new(1), &UserData { users }).expect("Failed to save UserData");
    });
}

/// Post-upgrade function to restore user data after upgrade
#[post_upgrade]
fn post_upgrade() {
    MEMORY.with(|memory| {
        let user_data: UserData = memory.load(MemoryId::new(1)).expect("Failed to load UserData");
        storage::set(user_data.users);
    });
}

/// Create a new user account (sign up)
#[update]
fn create_user(req: CreateUserRequest) -> String {
    let mut users = storage::get_mut::<HashMap<String, User>>();
    if users.contains_key(&req.username) {
        return "Username already exists".to_string();
    }
    
    let password_hash = hash_password(&req.password).expect("Failed to hash password");
    let new_user = User {
        username: req.username.clone(),
        password_hash,
        role: req.role,
        data: HashMap::new(),
    };
    
    users.insert(req.username, new_user);
    "User created successfully".to_string()
}

/// User login (sign in)
#[update]
fn login(req: LoginRequest) -> LoginResponse {
    let users = storage::get::<HashMap<String, User>>();
    
    if let Some(user) = users.get(&req.username) {
        if verify_password(&req.password, &user.password_hash).unwrap_or(false) {
            let token = generate_token(&req.username);
            return LoginResponse {
                success: true,
                message: "Login successful".to_string(),
                token: Some(AccessToken { token, username: req.username }),
            };
        }
    }
    
    LoginResponse {
        success: false,
        message: "Invalid username or password".to_string(),
        token: None,
    }
}

/// Store data associated with a user (encrypted before storing)
#[update]
fn store_data(token: String, key: String, value: String, expiration: Option<DateTime<Utc>>) -> String {
    let username = validate_token(&token).expect("Invalid token");
    let mut users = storage::get_mut::<HashMap<String, User>>();
    
    if let Some(user) = users.get_mut(&username) {
        let encrypted_value = encrypt_data(&value); // Encrypt data
        let data_entry = DataEntry {
            value: encrypted_value,
            timestamp: Utc::now(),
            expiration,
            shared_with: vec![],
        };
        user.data.insert(key, data_entry);
        return "Data stored successfully".to_string();
    }
    "Invalid token".to_string()
}

/// Read data associated with a user (decrypt before returning)
#[query]
fn read_data(req: DataRequest) -> DataResponse {
    let username = validate_token(&req.token).expect("Invalid token");
    let users = storage::get::<HashMap<String, User>>();
    
    if let Some(user) = users.get(&username) {
        if let Some(entry) = user.data.get(&req.key) {
            if entry.expiration.map_or(false, |exp| exp < Utc::now()) {
                return DataResponse {
                    success: false,
                    message: "Data has expired".to_string(),
                    data: None,
                };
            }
            let decrypted_data = decrypt_data(&entry.value);
            return DataResponse {
                success: true,
                message: "Data retrieved successfully".to_string(),
                data: Some(decrypted_data),
            };
        }
        return DataResponse {
            success: false,
            message: "Key not found".to_string(),
            data: None,
        };
    }
    DataResponse {
        success: false,
        message: "Invalid token".to_string(),
        data: None,
    }
}

/// Delete data associated with a user
#[update]
fn delete_data(token: String, key: String) -> String {
    let username = validate_token(&token).expect("Invalid token");
    let mut users = storage::get_mut::<HashMap<String, User>>();
    
    if let Some(user) = users.get_mut(&username) {
        if user.data.remove(&key).is_some() {
            return "Data deleted successfully".to_string();
        }
        return "Key not found".to_string();
    }
    "Invalid token".to_string()
}

/// Generate a secure JWT token
fn generate_token(username: &str) -> String {
    let my_claims = Claims { sub: username.to_string(), exp: Utc::now().timestamp() + 600 }; // 10 min token
    let header = Header::default();
    encode(&header, &my_claims, "your_secret_key".as_ref()).expect("Failed to generate token")
}

/// Validate the JWT token
fn validate_token(token: &str) -> Option<String> {
    let validation = Validation { leeway: 0, validate_exp: true, ..Default::default() };
    decode::<Claims>(&token, "your_secret_key".as_ref(), &validation)
        .map(|data| data.claims.sub)
        .ok()
}

/// Hash password securely
fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, bcrypt::DEFAULT_COST)
}

/// Verify hashed password
fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

/// Encrypt data using AES encryption
fn encrypt_data(data: &str) -> String {
    let key = b"example_key_16_byt"; // Example key, securely generated in real scenarios
    let iv = b"example_iv_16_bytes"; // Example IV, securely generated in real scenarios

    let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv).unwrap();
    let ciphertext = cipher.encrypt_vec(data.as_bytes());
    base64::encode(&ciphertext) // Return as base64
}

/// Decrypt data using AES encryption
fn decrypt_data(data: &str) -> String {
    let key = b"example_key_16_byt"; // Example key, securely generated in real scenarios
    let iv = b"example_iv_16_bytes"; // Example IV, securely generated in real scenarios

    let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(&base64::decode(data).unwrap()).unwrap();
    String::from_utf8(decrypted_data).unwrap() // Return decrypted data
}
