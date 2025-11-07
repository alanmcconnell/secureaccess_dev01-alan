# CSRF Cross-Origin Implementation Guide

## Understanding CSRF in Cross-Origin Context

Cross-Site Request Forgery (CSRF) attacks exploit the trust a web application has in an authenticated user's browser. When implementing CSRF protection for cross-origin requests (like between a frontend on `app.example.com` and an API on `api.example.com`), additional considerations are necessary beyond same-origin scenarios.

## Core CSRF Protection Methods

### 1. Double-Submit Cookie Pattern

This pattern works well for cross-origin scenarios when implemented correctly.

**Implementation Steps:**

```javascript
// Backend - Generate and set CSRF token
app.use((req, res, next) => {
  const csrfToken = generateSecureRandomToken();
  
  res.cookie('csrf-token', csrfToken, {
    httpOnly: false, // Must be readable by JavaScript
    secure: true,     // HTTPS only
    sameSite: 'none', // Allow cross-origin
    path: '/'
  });
  
  next();
});

// Frontend - Include token in requests
const csrfToken = getCookie('csrf-token');

fetch('https://api.example.com/endpoint', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken
  },
  body: JSON.stringify(data)
});

// Backend - Validate token
app.post('/endpoint', (req, res) => {
  const cookieToken = req.cookies['csrf-token'];
  const headerToken = req.headers['x-csrf-token'];
  
  if (!cookieToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  // Process request
});
```

### 2. Synchronizer Token Pattern with CORS

This pattern requires careful CORS configuration for cross-origin scenarios.

**Backend Configuration:**

```javascript
// CORS configuration
app.use(cors({
  origin: 'https://app.example.com',
  credentials: true,
  allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
  exposedHeaders: ['X-CSRF-Token']
}));

// Generate token endpoint
app.get('/csrf-token', (req, res) => {
  const token = generateSecureRandomToken();
  
  // Store token in session
  req.session.csrfToken = token;
  
  res.json({ csrfToken: token });
});

// Validate on protected endpoints
app.post('/api/protected', (req, res) => {
  const sessionToken = req.session.csrfToken;
  const providedToken = req.headers['x-csrf-token'];
  
  if (!sessionToken || sessionToken !== providedToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  // Process request
});
```

**Frontend Implementation:**

```javascript
// Fetch CSRF token
async function getCsrfToken() {
  const response = await fetch('https://api.example.com/csrf-token', {
    credentials: 'include'
  });
  const data = await response.json();
  return data.csrfToken;
}

// Make protected request
async function makeProtectedRequest(data) {
  const csrfToken = await getCsrfToken();
  
  const response = await fetch('https://api.example.com/api/protected', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify(data)
  });
  
  return response.json();
}
```

## Critical Security Configurations

### CORS Configuration

Proper CORS setup is essential for cross-origin CSRF protection:

```javascript
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://app.example.com',
      'https://www.example.com'
    ];
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Essential for cookies/sessions
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
```

### Cookie Security Settings

For cross-origin requests, configure cookies carefully:

```javascript
// For session cookies
app.use(session({
  cookie: {
    secure: true,        // HTTPS only
    httpOnly: true,      // Prevent XSS access
    sameSite: 'none',    // Allow cross-origin
    domain: '.example.com' // Share across subdomains if needed
  }
}));

// For CSRF tokens in cookies
res.cookie('csrf-token', token, {
  secure: true,
  httpOnly: false,     // Must be readable by JavaScript
  sameSite: 'none',    // Required for cross-origin
  path: '/'
});
```

## Additional Security Measures

### 1. Origin and Referer Validation

Add an extra layer by validating request origins:

```javascript
function validateOrigin(req, res, next) {
  const allowedOrigins = ['https://app.example.com'];
  const origin = req.headers.origin || req.headers.referer;
  
  if (!origin || !allowedOrigins.includes(new URL(origin).origin)) {
    return res.status(403).json({ error: 'Invalid origin' });
  }
  
  next();
}

app.use('/api/protected', validateOrigin);
```

### 2. Custom Request Headers

Leverage the fact that custom headers cannot be set by forms:

```javascript
// Frontend
fetch('https://api.example.com/api/endpoint', {
  headers: {
    'X-Requested-With': 'XMLHttpRequest'
  }
});

// Backend
app.use((req, res, next) => {
  if (req.method !== 'GET' && !req.headers['x-requested-with']) {
    return res.status(403).json({ error: 'Custom header required' });
  }
  next();
});
```

### 3. Token Rotation

Implement token rotation for enhanced security:

```javascript
class CSRFTokenManager {
  constructor() {
    this.tokens = new Map();
  }
  
  generateToken(sessionId) {
    const token = crypto.randomBytes(32).toString('hex');
    
    // Store with timestamp
    this.tokens.set(sessionId, {
      token,
      createdAt: Date.now(),
      used: false
    });
    
    // Clean old tokens
    this.cleanOldTokens();
    
    return token;
  }
  
  validateToken(sessionId, token) {
    const stored = this.tokens.get(sessionId);
    
    if (!stored || stored.token !== token) {
      return false;
    }
    
    // Check if expired (1 hour)
    if (Date.now() - stored.createdAt > 3600000) {
      this.tokens.delete(sessionId);
      return false;
    }
    
    // Mark as used and generate new token
    stored.used = true;
    return true;
  }
  
  cleanOldTokens() {
    const now = Date.now();
    for (const [key, value] of this.tokens.entries()) {
      if (now - value.createdAt > 3600000 || value.used) {
        this.tokens.delete(key);
      }
    }
  }
}
```

## Implementation Checklist

- ✅ **HTTPS Only**: Ensure all communication uses HTTPS
- ✅ **Secure Cookies**: Set `secure`, `httpOnly`, and appropriate `sameSite` flags
- ✅ **CORS Configuration**: Properly configure allowed origins and credentials
- ✅ **Token Generation**: Use cryptographically secure random tokens
- ✅ **Token Validation**: Validate tokens on all state-changing operations
- ✅ **Origin Validation**: Verify request origins as additional protection
- ✅ **Content-Type Validation**: Check Content-Type headers for API endpoints
- ✅ **Token Expiration**: Implement token expiration and rotation
- ✅ **Error Handling**: Return consistent error responses for security failures
- ✅ **Logging**: Log CSRF validation failures for monitoring

## Common Pitfalls to Avoid

1. **Using GET for State Changes**: Never use GET requests for operations that modify state
2. **Weak Token Generation**: Always use cryptographically secure random number generators
3. **Token in URL**: Never include CSRF tokens in URLs (can leak via referer)
4. **Missing Validation**: Validate tokens on all POST, PUT, DELETE, and PATCH requests
5. **Improper CORS**: Avoid using wildcard (*) for origins when credentials are included
6. **Token Reuse**: Consider implementing single-use tokens for sensitive operations
7. **Client-Side Token Storage**: Store tokens securely and clear them on logout

## Testing Your Implementation

```javascript
// Test script to verify CSRF protection
async function testCSRFProtection() {
  // Test 1: Request without token (should fail)
  try {
    const response1 = await fetch('https://api.example.com/protected', {
      method: 'POST',
      credentials: 'include'
    });
    console.log('No token test:', response1.status === 403 ? 'PASS' : 'FAIL');
  } catch (error) {
    console.log('No token test: FAIL', error);
  }
  
  // Test 2: Request with invalid token (should fail)
  try {
    const response2 = await fetch('https://api.example.com/protected', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-CSRF-Token': 'invalid-token'
      }
    });
    console.log('Invalid token test:', response2.status === 403 ? 'PASS' : 'FAIL');
  } catch (error) {
    console.log('Invalid token test: FAIL', error);
  }
  
  // Test 3: Request with valid token (should succeed)
  try {
    const tokenResponse = await fetch('https://api.example.com/csrf-token', {
      credentials: 'include'
    });
    const { csrfToken } = await tokenResponse.json();
    
    const response3 = await fetch('https://api.example.com/protected', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-CSRF-Token': csrfToken
      }
    });
    console.log('Valid token test:', response3.status === 200 ? 'PASS' : 'FAIL');
  } catch (error) {
    console.log('Valid token test: FAIL', error);
  }
}
```

## Conclusion

Implementing CSRF protection for cross-origin requests requires careful attention to CORS configuration, cookie settings, and token management. The combination of proper CSRF tokens with additional security measures like origin validation and secure cookie configuration provides robust protection against CSRF attacks while maintaining functionality for legitimate cross-origin requests.