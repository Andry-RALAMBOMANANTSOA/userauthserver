# **UserAuthServer**

UserAuthServer is a backend service built with Rust and Actix-Web for managing user authentication and account operations. It provides features like user signup, login, logout, profile management, and notifications through WebSocket. The server uses MongoDB for data storage and ensures high-security standards by implementing encrypted and hashed password storage, two-factor authentication (2FA), and secure session management.

## Features

**Authentication and Account Management**
-**Signup**: Register new users and store their information securely.
-**Signin**: Authenticate users using email/password and 2FA via Google Authenticator.
-**Logout**: End user sessions securely by also removing the token cookie inside the browser.
-**Profile Management**: Update and retrieve user profile information.
-**Password Recovery**: Reset forgotten passwords using OTP-based recovery.

**Security**
-**Password Encryption**: Passwords are hashed using Bcrypt, then encrypted with AES before being stored in the database.
-**Two-Factor Authentication (2FA)**: Use Google Authenticator for additional security during login. The 2FA key is also encrypted before being stored in the database.
-**Secure Cookies**: Session tokens are stored in cookies with `Secure` and `Lax` attributes. Cookies only work when the server runs on HTTPS.
-**Token Configuration**: Session tokens have a default expiration of 36,000 seconds for post-2FA checking and 600 seconds for pre-2FA checking, configurable via the .env file.

**Real-Time Notifications**
-Notify users of new messages in real time through `/ws/usermessage`.
-Broadcast news updates via `/ws/news`.

**Additional Functionalities**
-**KYC Management**: Submit and update Know Your Customer (KYC) information.
-**Security Settings**: Manage user-specific security preferences.

#**Technologies Used**
-**Framework**: Actix-Web
-**Database**: MongoDB
-**Security**:
AES encryption
Bcrypt hashing
JSON Web Tokens (JWT) for session management
-**WebSockets**: Real-time notifications
-**Environment Variables**: Configured via `.env` to store sensitive key
-**Reverse Proxy**: Compatible with Nginx for HTTPS enforcement

#**Routes**
**Authentication Routes**
`POST /signup` - Register a new user.
`POST /signin` - Log in using email and password.
`GET /logout` - Log out from the current session.
`POST /pass_recovery` - Start password recovery.
`POST /otprecovery` - Validate OTP for password recovery.
**2FA Routes**
`GET /twofacreatio`n - Generate a new 2FA secret.
`GET /twofavalidatestartup` - Validate 2FA setup.
`POST /twofavalidate` - Validate 2FA during login.
`POST /otp_renew` - Request OTP renewal.
`POST /otp_renew_validate` - Validate OTP renewal.
**Profile and Security Routes**
`GET /profile` - Fetch user profile.
`POST /profile_update` - Update profile information.
`GET /security` - Fetch security settings.
`POST /newpass` - Change password.
**KYC Routes**
`GET /kyc` - Fetch KYC information.
`POST /kyc_update` - Update KYC information.
**Web Content**
`POST /webcontent` - Fetch or update web content.
`GET /news` - Fetch latest news updates.
`GET /status` - Check server status.
**WebSocket Routes**
`GET /ws/news` - Real-time news updates.
`GET /ws/usermessage` - Notify users of new messages.

#**Environment Configuration**
Define the following variables in the `.env` file:

```bash
ONGO_URI=mongodb://localhost:27017
DB_USER=users
DB_COMPANY = your_company_name
COLLECTION_USER=basic
COLLECTION_USER_SENSITIVE=sensitive
COLLECTION_USER_SIGNINLOG = signinlog
COLLECTION_USER_LOGSTATE = logstate
COLLECTION_USER_MESSAGE = usermessage
COLLECTION_CONTENT = webcontent
COLLECTION_NEWS = news
TOKEN_SECRET = example@fdf4564gf6f4s54df684fsd4f68e
TOKEN_DURATION_BOTP=600
TOKEN_DURATION_AOTP=36000
CODE_DURATION = 300
ALLOWED_COUNTRY=Madagascar
APP_NAME=your_company_name
EMAIL_KEY = example@b30a8e471e3ba19b241b982d7714f1b8
SENDER_MAIL = mailtrap@demomailtrap.com
MAIL_TEMPLATE = 9b8ea052-f468-4e5e-a434-c6d51c58adef
TOTP_KEY =example@g4dfg54dfg53df4gdfgf58g4df5g4dg456
PASS_KEY = example@SK45D45F545gs5425D5468320Sb487if542E
SECRET_WORD_KEY =example@YKHJK1842ukla56sq8f4g2g48G5HFJT8h5jn8
```

