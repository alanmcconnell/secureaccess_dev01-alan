# System Specifications - SecureAccess

## System Architecture

### Backend Server
- **Framework**: Express.js 4.18.2
- **Runtime**: Node.js
- **Port**: 3000 (configurable)
- **Database**: MySQL 2.x connection pool

### Database Configuration
```
Host: localhost
Port: 3306
Database: secureaccess2
Connection Pool: 10 connections
```

### Security Implementation

#### JWT Configuration
- **Library**: jsonwebtoken 9.0.2
- **Algorithm**: HS256
- **Expiration**: 24 hours
- **Storage**: HTTP-only cookies + Authorization header fallback
- **Secret**: Environment variable (JWT_SECRET)

#### Password Security
- **Hashing**: bcrypt 5.1.1
- **Salt Rounds**: 12
- **Validation**: Server-side verification

## API Endpoints

### Authentication Routes
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/login` | User login | No |
| POST | `/api/auth/register` | User registration | No |
| POST | `/api/auth/logout` | User logout | Yes |
| GET | `/api/auth/verify` | Token verification | Yes |
| POST | `/api/auth/verify-admin` | Admin verification | Yes (Admin) |

### User Management Routes
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/users` | List all users | Yes (Admin) |
| GET | `/api/users/me` | Get own profile | Yes |
| GET | `/api/users/:id` | Get user by ID | Yes |
| POST | `/api/users` | Create user | Yes (Admin) |
| PUT | `/api/users/:id` | Update user | Yes (Admin) |
| PUT | `/api/users/me` | Update own profile | Yes |
| DELETE | `/api/users/:id` | Delete user | Yes (Admin) |

## Database Schema

### sa_users Table
```sql
CREATE TABLE sa_users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    master_password_hash VARCHAR(255) NOT NULL,
    account_status ENUM('active', 'inactive', 'locked') DEFAULT 'active',
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    role ENUM('User', 'Admin') DEFAULT 'User',
    security_question_1 TEXT,
    security_answer_1_hash VARCHAR(255),
    security_question_2 TEXT,
    security_answer_2_hash VARCHAR(255),
    token_expiration_minutes INT DEFAULT 60,
    last_login_timestamp TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

## Client Applications

### Login Client (`login_client.html`)
- **Features**: Login/Registration forms, JWT token handling
- **Security**: PKCE support, failed attempt tracking
- **Responsive**: Mobile-optimized design

### Admin Panel (`admin-page.html`)
- **Features**: User CRUD operations, role management
- **Security**: Admin-only access verification
- **Interface**: Grid-based user selection with form editing

### Profile Page (`profile-page.html`)
- **Features**: Self-service profile management
- **Security**: User-specific data access
- **Functionality**: Password change, security questions

## Security Features

### Authentication Flow
1. User submits credentials
2. Server validates against database
3. JWT token generated with user claims
4. Token stored in HTTP-only cookie
5. Subsequent requests include token
6. Server verifies token signature and expiration

### Authorization Levels
- **Public**: Registration, login endpoints
- **Authenticated**: Profile access, token verification
- **Admin**: User management, system administration

### Security Middleware
- **CORS**: Cross-origin request handling
- **Rate Limiting**: Request throttling protection
- **Input Validation**: SQL injection prevention
- **Password Hashing**: bcrypt with salt rounds

## Configuration

### Environment Variables
```
JWT_SECRET=SecureAccess-JWT-Secret-Key-2024!@#$%
PORT=3000
DB_HOST=localhost
DB_PORT=3306
DB_USER=nimdas
DB_PASSWORD=FormR!1234
DB_NAME=secureaccess2
```

### Dependencies
```json
{
  "bcrypt": "^5.1.1",
  "cookie-parser": "^1.4.7",
  "cors": "^2.8.5",
  "express": "^4.18.2",
  "express-rate-limit": "^7.1.5",
  "jsonwebtoken": "^9.0.2",
  "mysql2": "^3.6.0"
}
```

## Performance Specifications

### Response Times
- Authentication: < 500ms
- User queries: < 200ms
- Database operations: < 100ms

### Scalability
- Stateless JWT architecture
- Connection pooling for database
- Horizontal scaling ready

### Browser Support
- Modern browsers (ES6+ support)
- Mobile responsive design
- Progressive enhancement

---
*System Specifications v1.0 - January 2025*