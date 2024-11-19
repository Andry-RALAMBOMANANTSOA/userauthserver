# **UserAuthServer**

UserAuthServer is a backend service built with Rust and Actix-Web for managing user authentication and account operations. It provides features like user signup, login, logout, profile management, and notifications through WebSocket. The server uses MongoDB for data storage and ensures high-security standards by implementing encrypted and hashed password storage, two-factor authentication (2FA), and secure session management.

## Features

**Authentication and Account Management**
- **Signup**: Register new users and store their information securely.
- **Signin**: Authenticate users using email/password and 2FA via Google Authenticator.
- **Logout**: End user sessions securely by also removing the token cookies inside the browser.
- **Profile Management**: Update and retrieve user profile information.
- **Password Recovery**: Reset forgotten passwords using OTP-based recovery.

**Security**
- **Password Encryption**: Passwords are hashed using Bcrypt, then encrypted with AES before being stored in the database.
- **Two-Factor Authentication (2FA)**: Use Google Authenticator for additional security during login. The 2FA key is also encrypted before being stored in the database.
- **Secure Cookies**: Session tokens are stored in cookies with `Secure` and `Lax` attributes. Cookies only work when the server runs on HTTPS.
- **Token duration**: Session tokens have a default expiration of 36,000 seconds for post-2FA checking and 600 seconds for pre-2FA checking, configurable via the .env file.

**Real-Time Notifications**
- Notify users of new messages in real time through `/ws/usermessage`.
- Broadcast news updates via `/ws/news`.

**Additional Functionalities**
- **KYC Management**: Submit and update Know Your Customer (KYC) information.
- **Security Settings**: Manage user-specific security preferences.

## Technologies Used

- **Framework**: Actix-Web
- **Database**: MongoDB
- **Security**:AES encryption, Bcrypt hashing, JSON Web Tokens (JWT) for session management
- **WebSockets**: Real-time notifications
- **Environment Variables**: Configured via `.env` to store sensitive key
- **Reverse Proxy**: Compatible with Nginx for HTTPS enforcement

## Routes

**Authentication Routes**
- `POST /signup` - Register a new user.
- `POST /signin` - Log in using email and password.
- `GET /logout` - Log out from the current session.
- `POST /pass_recovery` - Start password recovery.
- `POST /otprecovery` - Validate OTP for password recovery.
  
**2FA Routes**
- `GET /twofacreatio`n - Generate a new 2FA secret.
- `GET /twofavalidatestartup` - Validate 2FA setup.
- `POST /twofavalidate` - Validate 2FA during login.
- `POST /otp_renew` - Request OTP renewal.
- `POST /otp_renew_validate` - Validate OTP renewal.
  
**Profile and Security Routes**
- `GET /profile` - Fetch user profile.
- `POST /profile_update` - Update profile information.
- `GET /security` - Fetch security settings.
- `POST /newpass` - Change password.
  
**KYC Routes**
- `GET /kyc` - Fetch KYC information.
- `POST /kyc_update` - Update KYC information.
  
**Web Content**
- `POST /webcontent` - Fetch or update web content.
- `GET /news` - Fetch latest news updates.
- `GET /status` - Check server status.
  
**WebSocket Routes**
- `GET /ws/news` - Real-time news updates.
- `GET /ws/usermessage` - Notify users of new messages.

## Environment Configuration

Define the following variables in the `.env` file:

```bash
MONGO_URI=mongodb://localhost:27017
DB_USER=users
DB_COMPANY = your_company_name
COLLECTION_USER=basic
COLLECTION_USER_SENSITIVE=sensitive
COLLECTION_USER_SIGNINLOG = signinlog
COLLECTION_USER_LOGSTATE = logstate
COLLECTION_USER_MESSAGE = usermessage
COLLECTION_CONTENT = webcontent
COLLECTION_NEWS = news
TOKEN_SECRET = example@fdf4564gfsd56f4sd5f4f68e
TOKEN_DURATION_BOTP=600
TOKEN_DURATION_AOTP=36000
CODE_DURATION = 300
ALLOWED_COUNTRY=Madagascar
APP_NAME=your_company_name
EMAIL_KEY = example@b30a8e475df419b241b982d715e1b8
SENDER_MAIL = mailtrap@demomailtrap.com
MAIL_TEMPLATE = 9b8ea052-f468-4e5e-a434-gdf5g456f44
TOTP_KEY =example@g4dfg54dfg53df4gdfg4d5g4r68
PASS_KEY = example@SK45D45F545gs5425D54df4sd56f4sd8e
SECRET_WORD_KEY =example@YKHJK1842ukla56sq8f4g2s4d5f64684
```
## Setup Instructions
1- **Clone the Repository**:

```bash
git clone https://github.com/<your-username>/UserAuthServer.git
cd UserAuthServer
```

2- **Install Dependencies**: Ensure you have Rust installed, then run:

```bash
cargo build --release
```

3- **Set Up MongoDB**: Configure your MongoDB connection URI in the .env file.

4- **Run the Server:**

```bash
cargo run --release
```

5- **Configure Nginx**: To enable HTTPS:

- Obtain an SSL certificate.
- Configure Nginx to reverse-proxy requests to the server.

  ## Example Nginx Configuration

 <pre>
server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate /path/to/certificate.pem;
    ssl_certificate_key /path/to/certificate-key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
</pre>
## License
This project is open-source and available under the MIT License. See the LICENSE file for details.

## Continuation and improvement
Developers may modify, add, delete functionalities and microservices.
