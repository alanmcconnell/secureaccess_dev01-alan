// Global Token Management Functions
// Server-side implementation (Node.js/Express)

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Configuration object for token settings
const tokenConfig = {
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    tokenExpiry: '1h',
    cookieName: 'authToken',
    csrfCookieName: 'csrf-token',
    cookieOptions: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // HTTPS in production
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour in milliseconds
        path: '/'
    }
};

// In-memory CSRF token storage (use Redis or database in production)
const csrfTokenStore = new Map();

/**
 * SA_SendToken - Global function to send/set JWT token
 * @param {Object} res - Express response object
 * @param {Object} userData - User data to encode in token
 * @param {String} userData.userId - User ID
 * @param {String} userData.email - User email
 * @param {Object} options - Optional configuration overrides
 * @returns {Object} - Returns token info and CSRF token
 */
function SA_SendToken(res, userData, options = {}) {
    try {
        // Merge default config with any provided options
        const config = { ...tokenConfig, ...options };
        
        // Generate JWT token with user data
        const tokenPayload = {
            userId: userData.userId,
            email: userData.email,
            issuedAt: Date.now(),
            // Add any additional claims as needed
            roles: userData.roles || [],
            permissions: userData.permissions || []
        };
        
        const token = jwt.sign(
            tokenPayload,
            config.jwtSecret,
            { expiresIn: config.tokenExpiry }
        );
        
        // Generate CSRF token
        const csrfToken = crypto.randomBytes(32).toString('hex');
        
        // Store CSRF token associated with user ID
        csrfTokenStore.set(userData.userId, {
            token: csrfToken,
            expires: Date.now() + config.cookieOptions.maxAge
        });
        
        // Set JWT as HTTP-only cookie
        res.cookie(config.cookieName, token, config.cookieOptions);
        
        // Set CSRF token as a readable cookie (not httpOnly)
        res.cookie(config.csrfCookieName, csrfToken, {
            ...config.cookieOptions,
            httpOnly: false // JavaScript needs to read this
        });
        
        // Return token info for logging or response
        return {
            success: true,
            csrfToken: csrfToken,
            expiresIn: config.tokenExpiry,
            userId: userData.userId
        };
        
    } catch (error) {
        console.error('SA_SendToken Error:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * SA_ReceiveToken - Global function to receive/verify JWT token
  * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @param {Object} options - Optional configuration
 * @returns {Object|void} - Returns decoded token or handles redirect
 */
function SA_ReceiveToken(req, res, next, options = {}) {
    try {
        const config = { ...tokenConfig, ...options };
        
        // Extract JWT from HTTP-only cookie
        const token = req.cookies[config.cookieName];
        
        // Check if token exists
        if (!token) {
            if (next) {
                return res.status(401).json({ 
                    success: false, 
                    error: 'No authentication token provided' 
                });
            } else {
                // For server-side rendering, redirect to login
                return res.redirect('/login?error=no_token');
            }
        }
        
        // Verify JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, config.jwtSecret);
        } catch (jwtError) {
            if (jwtError.name === 'TokenExpiredError') {
                // Clear expired cookies
                res.clearCookie(config.cookieName);
                res.clearCookie(config.csrfCookieName);
                
                if (next) {
                    return res.status(401).json({ 
                        success: false, 
                        error: 'Token expired' 
                    });
                } else {
                    return res.redirect('/login?error=token_expired');
                }
            }
            throw jwtError;
        }
        
        // Verify CSRF token if present in headers
        const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
        if (csrfToken) {
            const storedCSRF = csrfTokenStore.get(decoded.userId);
            
            if (!storedCSRF || storedCSRF.token !== csrfToken) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Invalid CSRF token' 
                });
            }
            
            // Check CSRF token expiration
            if (storedCSRF.expires < Date.now()) {
                csrfTokenStore.delete(decoded.userId);
                return res.status(403).json({ 
                    success: false, 
                    error: 'CSRF token expired' 
                });
            }
        }
        
        // Attach user info to request object for downstream use
        req.user = {
            userId: decoded.userId,
            email: decoded.email,
            roles: decoded.roles || [],
            permissions: decoded.permissions || [],
            tokenIssuedAt: decoded.issuedAt
        };
        
        // Optional: Refresh token if close to expiration
        const tokenAge = Date.now() - decoded.issuedAt;
        const maxAge = config.cookieOptions.maxAge;
        
        if (tokenAge > maxAge * 0.75) { // If 75% through lifetime
            // Refresh the token
            const refreshResult = SA_SendToken(res, req.user, options);
            if (refreshResult.success) {
                console.log(`Token refreshed for user ${req.user.userId}`);
            }
        }
        
        // If middleware function, continue to next
        if (next && typeof next === 'function') {
            return next();
        }
        
        // Return decoded user data
        return {
            success: true,
            user: req.user
        };
        
    } catch (error) {
        console.error('SA_ReceiveToken Error:', error);
        
        if (next) {
            return res.status(401).json({ 
                success: false, 
                error: 'Authentication failed' 
            });
        } else {
            return res.redirect('/login?error=auth_failed');
        }
    }
}

/**
 * Middleware wrapper for SA_ReceiveToken
 * Use this for Express route protection
 */
const requireAuth = (options = {}) => {
    return (req, res, next) => {
        return SA_ReceiveToken(req, res, next, options);
    };
};

/**
 * Helper function to clear authentication
 * Use for logout functionality
 */
function SA_ClearToken(res, userId) {
    try {
        // Clear cookies
        res.clearCookie(tokenConfig.cookieName);
        res.clearCookie(tokenConfig.csrfCookieName);
        
        // Clear CSRF token from store
        if (userId) {
            csrfTokenStore.delete(userId);
        }
        
        return {
            success: true,
            message: 'Authentication cleared successfully'
        };
    } catch (error) {
        console.error('SA_ClearToken Error:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Export functions for use throughout application
module.exports = {
    SA_SendToken,
    SA_ReceiveToken,
    requireAuth,
    SA_ClearToken,
    tokenConfig
};

/* ===============================================
   USAGE EXAMPLES
   =============================================== */

/*
// 1. LOGIN ROUTE - Initial token creation
app.post('/login', async (req, res) => {
    // Authenticate user
    const user = await authenticateUser(req.body.email, req.body.password);
    
    if (user) {
        // Send token using global function
        const tokenResult = SA_SendToken(res, {
            userId: user.id,
            email: user.email,
            roles: user.roles
        });
        
        if (tokenResult.success) {
            res.json({
                success: true,
                csrfToken: tokenResult.csrfToken,
                redirectUrl: '/dashboard'
            });
        }
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// 2. PROTECTED ROUTE - Using middleware
app.get('/dashboard', requireAuth(), (req, res) => {
    // req.user is now available with decoded token data
    res.render('dashboard', { user: req.user });
});

// 3. API ENDPOINT - Using middleware
app.get('/api/user/profile', requireAuth(), async (req, res) => {
    // req.user is available here
    const profile = await getUserProfile(req.user.userId);
    res.json(profile);
});

// 4. MANUAL VERIFICATION - Without middleware
app.get('/special-page', (req, res) => {
    const authResult = SA_ReceiveToken(req, res, null);
    
    if (authResult.success) {
        // User is authenticated
        res.render('special-page', { user: authResult.user });
    }
    // If not authenticated, SA_ReceiveToken already handled redirect
});

// 5. LOGOUT ROUTE
app.post('/logout', requireAuth(), (req, res) => {
    SA_ClearToken(res, req.user.userId);
    res.json({ success: true, message: 'Logged out successfully' });
});
*/