# SecureAccess Application Specifications v1.02

## Project Overview

SecureAccess is a comprehensive authentication and user management system designed for enterprise-grade security. The application provides secure user registration, authentication, profile management, and administrative capabilities with advanced security features including JWT tokens, two-factor authentication, and role-based access control.

## Architecture

### System Architecture
- **Frontend**: Responsive web application (HTML5, CSS3, Vanilla JavaScript)
- **Backend**: Node.js with Express.js RESTful API
- **Database**: MySQL with connection pooling
- **Authentication**: JWT-based with refresh token rotation
- **Security**: bcrypt password hashing, rate limiting, CORS protection

### Technology Stack

#### Frontend Technologies
- **HTML5**: Semantic markup with accessibility features
- **CSS3**: Custom responsive design with flexbox/grid
- **JavaScript**: ES6+ vanilla JavaScript (no frameworks)
- **External Libraries**:
  - QRious v4.0.2 (QR code generation)
  - CDN-hosted dependencies

#### Backend Technologies
- **Runtime**: Node.js
- **Framework**: Express.js v4.18.2
- **Database Driver**: mysql2 v3.6.0
- **Authentication**: jsonwebtoken v9.0.2
- **Password Hashing**: bcrypt v5.1.1
- **2FA**: speakeasy v2.0.0
- **Validation**: joi v17.11.0
- **Security**: express-rate-limit v7.1.5, cors v2.8.5
- **Environment**: dotenv v16.3.1

## Application Features

### Core Authentication Features
1. **User Registration**
   - First name, last name, username, email
   - Secure password with strength validation
   - Optional security questions (2 questions)
   - Optional two-factor authentication setup
   - Configurable token expiration (30min - 8hrs)

2. **User Login**
   - Username/email + password authentication
   - Optional 2FA code verification
   - JWT token generation with refresh capability
   - Session tracking and management

3. **Password Management**
   - Secure password reset via security questions
   - Password strength requirements
   - bcrypt hashing with unique salts
   - Password change functionality

4. **Two-Factor Authentication**
   - TOTP-based 2FA using authenticator apps
   - QR code generation for easy setup
   - Secret key backup display
   - Enable/disable 2FA functionality

### User Management Features
1. **Profile Management**
   - Update personal information
   - Change password
   - Modify security questions
   - Toggle 2FA settings
   - Adjust token expiration preferences

2. **Account Status Management**
   - Active, Inactive, Locked status options
   - Last login timestamp tracking
   - Account creation date logging
   - Session history

### Administrative Features
1. **Admin Dashboard**
   - User grid with search functionality
   - Comprehensive user form editing
   - Real-time user status updates
   - Bulk user management capabilities

2. **User Administration**
   - Create new users
   - Edit existing user profiles
   - Delete users with confirmation
   - Role assignment (User/Admin)
   - Account status management

3. **Security Administration**
   - JWT token management
   - Session monitoring
   - Audit log access
   - Security settings configuration

## Database Schema

### Core Tables

#### users
```sql
- user_id (INT, PRIMARY KEY, AUTO_INCREMENT)
- first_name (VARCHAR(100), NOT NULL)
- last_name (VARCHAR(100), NOT NULL)
- username (VARCHAR(255), UNIQUE, NOT NULL)
- email (VARCHAR(255), UNIQUE, NOT NULL)
- master_password_hash (VARCHAR(255), NOT NULL)
- salt (VARCHAR(255), NOT NULL)
- account_creation_date (TIMESTAMP, DEFAULT CURRENT_TIMESTAMP)
- last_login_timestamp (TIMESTAMP, NULL)
- account_status (ENUM: 'active', 'inactive', 'locked', DEFAULT 'active')
- security_question_1 (TEXT)
- security_answer_1_hash (VARCHAR(255))
- security_question_2 (TEXT)
- security_answer_2_hash (VARCHAR(255))
- two_factor_enabled (BOOLEAN, DEFAULT FALSE)
- two_factor_secret (VARCHAR(255))
- jwt_secret_version (INT, DEFAULT 1)
- refresh_token_rotation_enabled (BOOLEAN, DEFAULT TRUE)
- token_expiration_minutes (INT, DEFAULT 60)
- role (VARCHAR(50), DEFAULT 'User')
- created_at (TIMESTAMP, DEFAULT CURRENT_TIMESTAMP)
- updated_at (TIMESTAMP, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)
```

#### user_sessions
```sql
- session_id (INT, PRIMARY KEY, AUTO_INCREMENT)
- user_id (INT, FOREIGN KEY)
- session_token (VARCHAR(500), NOT NULL)
- ip_address (VARCHAR(45))
- device_info (TEXT)
- user_agent (TEXT)
- login_timestamp (TIMESTAMP, DEFAULT CURRENT_TIMESTAMP)
- expiration_timestamp (TIMESTAMP, NOT NULL)
- active_status (BOOLEAN, DEFAULT TRUE)
```

#### jwt_tokens
```sql
- token_id (INT, PRIMARY KEY, AUTO_INCREMENT)
- user_id (INT, FOREIGN KEY)
- token_type (ENUM: 'access', 'refresh', NOT NULL)
- jwt_token_hash (VARCHAR(255), NOT NULL)
- jti (VARCHAR(255), UNIQUE, NOT NULL)
- claims_summary (JSON)
- issue_timestamp (TIMESTAMP, DEFAULT CURRENT_TIMESTAMP)
- expiration_timestamp (TIMESTAMP, NOT NULL)
- revoked_status (BOOLEAN, DEFAULT FALSE)
- revocation_timestamp (TIMESTAMP, NULL)
- token_family_id (VARCHAR(255))
- device_info (TEXT)
- ip_address (VARCHAR(45))
```

#### audit_log
```sql
- log_id (INT, PRIMARY KEY, AUTO_INCREMENT)
- user_id (INT, FOREIGN KEY)
- jwt_token_id (INT, FOREIGN KEY)
- action_type (VARCHAR(100), NOT NULL)
- target_account_service (VARCHAR(255))
- target_resource (VARCHAR(255))
- ip_address (VARCHAR(45))
- user_agent (TEXT)
- timestamp (TIMESTAMP, DEFAULT CURRENT_TIMESTAMP)
- success_status (BOOLEAN, NOT NULL)
- error_message (TEXT)
- additional_data (JSON)
```

## API Endpoints

### Authentication Endpoints
- `POST /api/auth/login` - User authentication
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Token refresh
- `POST /api/auth/verify-admin` - Admin access verification
- `POST /api/auth/password-reset-request` - Password reset request
- `POST /api/auth/password-reset` - Password reset execution

### User Management Endpoints
- `GET /api/users` - List all users (admin only)
- `GET /api/users/:id` - Get user details
- `POST /api/users` - Create new user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user (admin only)

### Health Check
- `GET /health` - Server health status

## Security Features

### Authentication Security
1. **JWT Token Management**
   - Secure token generation with user-specific secrets
   - Configurable expiration times
   - Token refresh mechanism
   - Blacklist support for revoked tokens

2. **Password Security**
   - bcrypt hashing with unique salts
   - Minimum password strength requirements
   - Secure password reset flow
   - Password change tracking

3. **Two-Factor Authentication**
   - TOTP-based implementation
   - QR code generation for setup
   - Secret key management
   - Backup codes (future enhancement)

### Application Security
1. **Rate Limiting**
   - General API: 100 requests per 15 minutes
   - Authentication: 20 requests per 15 minutes
   - Password reset: 3 requests per 15 minutes

2. **Input Validation**
   - Joi schema validation
   - SQL injection prevention
   - XSS protection
   - CSRF protection

3. **Access Control**
   - Role-based permissions (User/Admin)
   - JWT-based authorization
   - Session management
   - Admin-only endpoints protection

## User Interface Specifications

### Design System
- **Color Scheme**: Purple gradient theme (#667eea to #764ba2)
- **Typography**: System fonts (-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto)
- **Layout**: Responsive flexbox/grid design
- **Components**: Custom CSS components with hover effects

### Responsive Design
- **Desktop**: Optimized for 1200px+ screens
- **Tablet**: Responsive layout for 768px-1199px
- **Mobile**: Mobile-first design for 320px-767px
- **Touch**: Touch-optimized controls and spacing

### User Experience Features
1. **Interactive Elements**
   - Smooth animations and transitions
   - Hover effects on buttons and links
   - Loading states with spinners
   - Form validation feedback

2. **Accessibility**
   - Semantic HTML structure
   - Keyboard navigation support
   - Screen reader compatibility
   - High contrast support

3. **Feedback Systems**
   - Success/error alert messages
   - Form validation indicators
   - Loading states
   - Confirmation dialogs

## Application Pages

### 1. Login Page (`login_client.html`)
- **Features**: Login form, registration form, password reset
- **Components**: Tabbed interface, 2FA input, security questions
- **Functionality**: JWT token generation, session management

### 2. Landing Page (`landingpage.html`)
- **Features**: User dashboard, token analysis, navigation
- **Components**: User info display, token status, debug information
- **Functionality**: Token validation, user data display

### 3. Admin Page (`admin-page.html`)
- **Features**: User management interface, admin controls
- **Components**: User grid, edit forms, action buttons
- **Functionality**: CRUD operations, role management, user administration

## Configuration

### Environment Variables
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=nimdas
DB_PASSWORD=FormR!1234
DB_NAME=secureaccess2
JWT_SECRET=your-secret-key
PORT=3000
NODE_ENV=development
```

### Server Configuration
- **Port**: 3000 (configurable via environment)
- **CORS**: Configured for cross-origin requests
- **Rate Limiting**: Multiple tiers based on endpoint sensitivity
- **Database**: Connection pooling with mysql2

## Deployment Specifications

### System Requirements
- **Node.js**: v16.0.0 or higher
- **MySQL**: v8.0 or higher
- **Memory**: Minimum 512MB RAM
- **Storage**: 1GB available space
- **Network**: HTTP/HTTPS support

### Installation Steps
1. Clone repository
2. Install dependencies: `npm install`
3. Configure environment variables
4. Set up MySQL database
5. Run database migrations
6. Start server: `npm start`

### Production Considerations
- HTTPS certificate configuration
- Database backup strategy
- Log rotation and monitoring
- Load balancing setup
- Security hardening

## Testing Strategy

### Frontend Testing
- Cross-browser compatibility testing
- Responsive design validation
- User interaction testing
- Accessibility compliance testing

### Backend Testing
- API endpoint testing
- Database integration testing
- Security vulnerability testing
- Performance and load testing

### Security Testing
- JWT token validation testing
- Authentication flow testing
- Authorization testing
- Input validation testing

## Future Enhancements

### Planned Features
1. **Enhanced Security**
   - Backup codes for 2FA
   - Biometric authentication support
   - Advanced audit logging

2. **User Experience**
   - Dark mode theme
   - Multi-language support
   - Advanced user preferences

3. **Administrative Features**
   - Bulk user operations
   - Advanced reporting
   - System monitoring dashboard

4. **Integration Capabilities**
   - LDAP/Active Directory integration
   - SSO provider support
   - API key management

## Version History

### v1.02 (Current)
- Real JWT token implementation
- Admin page optimization
- Enhanced security features
- Improved responsive design

### v1.01
- Initial implementation
- Basic authentication system
- User management features
- Database schema design

---

**Document Version**: 1.02  
**Last Updated**: January 2025  
**Author**: SecureAccess Development Team  
**Status**: Active Development