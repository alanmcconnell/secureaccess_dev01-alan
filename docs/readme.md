# Server First API - Secure User Management

A RESTful API server built with Express.js and MySQL for managing users in the `secureaccess` database with comprehensive security features including password hashing, 2FA, and security questions.

## Features

- **Secure Password Storage** - bcrypt hashing with custom salts
- **Two-Factor Authentication** - TOTP support with QR codes
- **Security Questions** - Optional security question/answer pairs
- **Account Management** - Account status tracking (active/inactive/locked)
- **JWT Integration Ready** - JWT secret versioning and token expiration control
- **Comprehensive User Schema** - Full user profile with security metadata
- **Input Validation** - Joi schema validation for all endpoints

## Setup Instructions

### 1. Install Dependencies
```bash
npm install
```

### 2. Database Setup
Make sure you have MySQL running locally and create the database:
```sql
CREATE DATABASE secureaccess;
```

### 3. Environment Configuration
Update the `.env` file with your MySQL credentials:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_actual_password
DB_NAME=secureaccess
DB_PORT=3306
PORT=3000
```

### 4. Start the Server
```bash
# Development mode with auto-restart
npm run dev

# Production mode
npm start
```

The server will automatically create the `users` table with the secure schema if it doesn't exist.

## API Endpoints

### Base URL: `http://localhost:3000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Welcome message and API info |
| GET | `/health` | Health check |
| GET | `/api/users` | Get all users |
| GET | `/api/users/:id` | Get user by ID |
| GET | `/api/users/:id/security` | Get user security info |
| POST | `/api/users` | Create new user |
| PUT | `/api/users/:id` | Update user |
| PATCH | `/api/users/:id/login` | Update last login timestamp |
| DELETE | `/api/users/:id` | Delete user |

## User Schema

The `users` table includes comprehensive security features:

```sql
CREATE TABLE users (
  user_id INT NOT NULL AUTO_INCREMENT,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  username VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  master_password_hash VARCHAR(255) NOT NULL,
  salt VARCHAR(255) NOT NULL,
  account_creation_date TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_timestamp TIMESTAMP NULL DEFAULT NULL,
  account_status ENUM('active','inactive','locked') DEFAULT 'active',
  security_question_1 TEXT,
  security_answer_1_hash VARCHAR(255) DEFAULT NULL,
  security_question_2 TEXT,
  security_answer_2_hash VARCHAR(255) DEFAULT NULL,
  two_factor_enabled TINYINT(1) DEFAULT '0',
  two_factor_secret VARCHAR(255) DEFAULT NULL,
  jwt_secret_version INT DEFAULT '1',
  refresh_token_rotation_enabled TINYINT(1) DEFAULT '1',
  token_expiration_minutes INT DEFAULT '60',
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  UNIQUE KEY username (username),
  UNIQUE KEY email (email)
);
```

## API Usage Examples

### Create a User with Security Features
```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "security_question_1": "What is your favorite color?",
    "security_answer_1": "Blue",
    "security_question_2": "What city were you born in?",
    "security_answer_2": "New York",
    "two_factor_enabled": true,
    "token_expiration_minutes": 120
  }'
```

### Update User Account Status
```bash
curl -X PUT http://localhost:3000/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{
    "account_status": "locked",
    "two_factor_enabled": false
  }'
```

### Update Last Login
```bash
curl -X PATCH http://localhost:3000/api/users/1/login
```

### Get User Security Information
```bash
curl http://localhost:3000/api/users/1/security
```

### Get All Users
```bash
curl http://localhost:3000/api/users
```

## Security Features

### Password Security
- **bcrypt hashing** with 12 rounds
- **Custom salt** generation for each user
- **Password updates** increment JWT secret version

### Two-Factor Authentication
- **TOTP support** using speakeasy
- **QR code generation** for easy setup
- **Base32 secret** storage

### Security Questions
- **Hashed answers** with user's salt
- **Case-insensitive** answer comparison
- **Optional** security question pairs

### Account Management
- **Account status** tracking (active/inactive/locked)
- **Last login** timestamp tracking
- **JWT secret versioning** for token invalidation
- **Configurable token expiration**

## Validation Rules

### User Creation
- `first_name`: Required, max 100 characters
- `last_name`: Required, max 100 characters
- `username`: Required, max 255 characters, must be unique
- `email`: Required, valid email format, max 255 characters, must be unique
- `password`: Required, minimum 8 characters
- `security_question_1/2`: Optional text
- `security_answer_1/2`: Optional, required if question provided
- `two_factor_enabled`: Boolean, default false
- `token_expiration_minutes`: Integer, 1-1440 minutes, default 60

### User Updates
- All fields optional for updates
- Same validation rules apply when provided
- Password changes increment JWT secret version
- 2FA toggle regenerates secret when enabled

## Response Format

### Success Response
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { /* response data */ }
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error description",
  "details": ["Validation error details"]
}
```

### Two-Factor Setup Response
When creating a user with 2FA enabled:
```json
{
  "success": true,
  "message": "User created successfully",
  "data": { /* user data */ },
  "twoFactorSetup": {
    "secret": "BASE32SECRET",
    "qrCodeUrl": "otpauth://totp/..."
  }
}
```

## Security Considerations

This implementation includes production-ready security features:

- ✅ **Password hashing** with bcrypt and salts
- ✅ **Input validation** with Joi schemas
- ✅ **SQL injection protection** with parameterized queries
- ✅ **Two-factor authentication** support
- ✅ **Security question hashing**
- ✅ **JWT secret versioning** for token invalidation
- ✅ **Account status management**
- ✅ **Unique constraints** on username and email
- ✅ **Database indexes** for performance

## Project Structure

```
server/s01_server-first-api/
├── controllers/
│   └── usersController.js
├── routes/
│   └── users.js
├── .env
├── database.js
├── server.js
├── package.json
└── README.md
```api/users` | Create new user |
| PUT | `/api/users/:id` | Update user |
| DELETE | `/api/users/:id` | Delete user |

## User Schema

The `users` table has the following structure:

```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

## API Usage Examples

### Create a User
```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Get All Users
```bash
curl http://localhost:3000/api/users
```

### Get User by ID
```bash
curl http://localhost:3000/api/users/1
```

### Update User
```bash
curl -X PUT http://localhost:3000/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Jane",
    "email": "jane@example.com"
  }'
```

### Delete User
```bash
curl -X DELETE http://localhost:3000/api/users/1
```

## Response Format

All API responses follow this format:

### Success Response
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { /* response data */ }
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error description",
  "error": "Detailed error message"
}
```

## Security Notes

**Important**: This is a basic implementation for development purposes. For production use, consider:

- Password hashing (bcrypt)
- Input validation and sanitization
- Authentication middleware (JWT)
- Rate limiting
- SQL injection protection (already implemented with parameterized queries)
- Environment variable validation
- HTTPS enforcement
- Request body size limits

## Project Structure

```
server/s01_server-first-api/
├── controllers/
│   └── usersController.js
├── routes/
│   └── users.js
├── .env
├── database.js
├── server.js
├── package.json
└── README.md
```