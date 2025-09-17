// Parameterless Global Token Management Functions
// Using AsyncLocalStorage for request context and database for user data

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');

// Create async context storage for request/response objects
const requestContext = new AsyncLocalStorage();

// Configuration object for token settings
const tokenConfig = {
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    tokenExpiry: '1h',
    cookieName: 'authToken',
    csrfCookieName: 'csrf-token',
    cookieOptions: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour
        path: '/'
    }
};

// Database functions (implement these based on your database)
// Using generic examples that you'll replace with your actual DB calls
async function getUserFromDatabase(userId) {
    // Replace with your actual database query
    // Example: SELECT * FROM users WHERE id = userId
    const user = await db.query('SELECT * FROM sa_users WHERE user_id = ?', [userId]);
    return user;
}

async function storeCSRFToken(userId, csrfToken, expires) {
    // Replace with your actual database query
    // Example: UPDATE users SET csrf_token = ?, csrf_expires = ? WHERE id = ?
    await db.query(
        'UPDATE sa_users SET csrf_token = ?, csrf_expires = ? WHERE user_id = ?',
        [csrfToken, expires, userId]
    );
}

async function getStoredCSRFToken(userId) {
    // Replace with your actual database query
    const result = await db.query(
        'SELECT csrf_token, csrf_expires FROM sa_users WHERE user_id = ?',
        [userId]
    );
    return result;
}

async function clearUserTokens(userId) {
    // Clear CSRF token from database
    await db.query(
        'UPDATE sa_users SET csrf_token = NULL, csrf_expires = NULL WHERE user_id = ?',
        [userId]
    );
}

/**
 * Middleware to initialize request context
 * This MUST be added before any routes that use SA_ functions
 */
function initializeContext(req, res, next) {
    // Store request and response in context
    requestContext.run({ req, res }, () => {
        next();
    });
}

/**
 * Helper function to get current context
 */
function getContext() {
    const context = requestContext.getStore();
    if (!context) {
        throw new Error('SA_ functions must be called within request context. Add initializeContext middleware.');
    }
    return context;
}

/**
 * SA_SendToken - Parameterless token sending
 * Gets all needed data from context and database
 */
async function SA_SendToken() {
    try {
        // Get request/response from context
        const { req, res } = getContext();
        
        // Get user ID from request (set during login or previous auth)
        const userId = req.userId || req.user?.userId;
        
        if (!userId) {
            throw new Error('User ID not found in request context');
        }
        
        // Fetch user data from database
        const userData = await getUserFromDatabase(userId);
        
        if (!userData) {
            throw new Error('User not found in database');
        }
        
        // Generate JWT token with user data from database
        const tokenPayload = {
            userId: userData.id,
            email: userData.email,
            issuedAt: Date.now(),
            roles: userData.roles || [],
            permissions: userData.permissions || []
        };
        
        const token = jwt.sign(
            tokenPayload,
            tokenConfig.jwtSecret,
            { expiresIn: tokenConfig.tokenExpiry }
        );
        
        // Generate CSRF token
        const csrfToken = crypto.randomBytes(32).toString('hex');
        const csrfExpires = new Date(Date.now() + tokenConfig.cookieOptions.maxAge);
        
        // Store CSRF token in database
        await storeCSRFToken(userData.id, csrfToken, csrfExpires);
        
        // Set JWT as HTTP-only cookie
        res.cookie(tokenConfig.cookieName, token, tokenConfig.cookieOptions);
        
        // Set CSRF token as readable cookie
        res.cookie(tokenConfig.csrfCookieName, csrfToken, {
            ...tokenConfig.cookieOptions,
            httpOnly: false
        });
        
        // Store user info in request for current request use
        req.user = {
            userId: userData.id,
            email: userData.email,
            roles: userData.roles,
            permissions: userData.permissions
        };
        
        return {
            success: true,
            message: 'Token sent successfully'
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
 * SA_ReceiveToken - Parameterless token verification
 * Gets all needed data from context and database
 */
async function SA_ReceiveToken() {
    try {
        // Get request/response from context
        const { req, res } = getContext();
        
        // Extract JWT from HTTP-only cookie
        const token = req.cookies[tokenConfig.cookieName];
        
        // Check if token exists
        if (!token) {
            // For API routes
            if (req.xhr || req.headers.accept?.includes('json')) {
                res.status(401).json({ 
                    success: false, 
                    error: 'No authentication token provided' 
                });
                return { success: false, redirect: false };
            }
            // For page routes
            res.redirect('/login?error=no_token');
            return { success: false, redirect: true };
        }
        
        // Verify JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, tokenConfig.jwtSecret);
        } catch (jwtError) {
            if (jwtError.name === 'TokenExpiredError') {
                // Clear expired cookies
                res.clearCookie(tokenConfig.cookieName);
                res.clearCookie(tokenConfig.csrfCookieName);
                
                // Clear from database
                if (decoded?.userId) {
                    await clearUserTokens(decoded.userId);
                }
                
                if (req.xhr || req.headers.accept?.includes('json')) {
                    res.status(401).json({ 
                        success: false, 
                        error: 'Token expired' 
                    });
                    return { success: false, redirect: false };
                }
                
                res.redirect('/login?error=token_expired');
                return { success: false, redirect: true };
            }
            throw jwtError;
        }
        
        // Fetch fresh user data from database
        const userData = await getUserFromDatabase(decoded.userId);
        
        if (!userData) {
            res.status(401).json({ 
                success: false, 
                error: 'User not found' 
            });
            return { success: false };
        }
        
        // Verify CSRF token if present
        const csrfToken = req.headers['x-csrf-token'] || req.body?._csrf;
        if (csrfToken) {
            const storedCSRF = await getStoredCSRFToken(decoded.userId);
            
            if (!storedCSRF || storedCSRF.csrf_token !== csrfToken) {
                res.status(403).json({ 
                    success: false, 
                    error: 'Invalid CSRF token' 
                });
                return { success: false };
            }
            
            // Check CSRF token expiration
            if (new Date(storedCSRF.csrf_expires) < new Date()) {
                await clearUserTokens(decoded.userId);
                res.status(403).json({ 
                    success: false, 
                    error: 'CSRF token expired' 
                });
                return { success: false };
            }
        }
        
        // Attach fresh user info to request object
        req.user = {
            userId: userData.id,
            email: userData.email,
            roles: userData.roles || [],
            permissions: userData.permissions || [],
            tokenIssuedAt: decoded.issuedAt
        };
        
        // Store userId for SA_SendToken to use if needed
        req.userId = userData.id;
        
        // Auto-refresh token if close to expiration
        const tokenAge = Date.now() - decoded.issuedAt;
        const maxAge = tokenConfig.cookieOptions.maxAge;
        
        if (tokenAge > maxAge * 0.75) {
            // Token is 75% through lifetime, refresh it
            await SA_SendToken();
            console.log(`Token auto-refreshed for user ${userData.id}`);
        }
        
        return {
            success: true,
            user: req.user
        };
        
    } catch (error) {
        console.error('SA_ReceiveToken Error:', error);
        
        const { res } = getContext();
        
        if (req.xhr || req.headers.accept?.includes('json')) {
            res.status(401).json({ 
                success: false, 
                error: 'Authentication failed' 
            });
            return { success: false, redirect: false };
        }
        
        res.redirect('/login?error=auth_failed');
        return { success: false, redirect: true };
    }
}

/**
 * SA_ClearToken - Parameterless token clearing (logout)
 */
async function SA_ClearToken() {
    try {
        const { req, res } = getContext();
        
        // Get user ID from request
        const userId = req.user?.userId || req.userId;
        
        // Clear cookies
        res.clearCookie(tokenConfig.cookieName);
        res.clearCookie(tokenConfig.csrfCookieName);
        
        // Clear from database if user ID exists
        if (userId) {
            await clearUserTokens(userId);
        }
        
        // Clear user from request
        delete req.user;
        delete req.userId;
        
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

/**
 * Middleware wrapper for protected routes
 * Automatically calls SA_ReceiveToken
 */
function requireAuth() {
    return async (req, res, next) => {
        // Ensure we're in context
        requestContext.run({ req, res }, async () => {
            const result = await SA_ReceiveToken();
            
            if (result.success) {
                next();
            } else if (!result.redirect) {
                // If not already redirected, send error
                res.status(401).json({ 
                    error: 'Authentication required' 
                });
            }
        });
    };
}

// Export functions and middleware
module.exports = {
    initializeContext,  // MUST be added as middleware first
    SA_SendToken,       // No parameters needed
    SA_ReceiveToken,    // No parameters needed
    SA_ClearToken,      // No parameters needed
    requireAuth         // Middleware for protected routes
};

/* ===============================================
   SETUP AND USAGE
   =============================================== */

/*
// 1. EXPRESS APP SETUP - Add context middleware FIRST
const express = require('express');
const cookieParser = require('cookie-parser');
const { initializeContext, SA_SendToken, SA_ReceiveToken, SA_ClearToken, requireAuth } = require('./token-functions');

const app = express();

// CRITICAL: Add these middlewares in this order
app.use(cookieParser());
app.use(express.json());
app.use(initializeContext);  // <-- MUST be added before any routes using SA_ functions

// 2. LOGIN ROUTE - Set userId in request, then call SA_SendToken
app.post('/login', async (req, res) => {
    requestContext.run({ req, res }, async () => {
        try {
            // Authenticate user (your own logic)
            const user = await authenticateUser(req.body.email, req.body.password);
            
            if (user) {
                // Set userId in request for SA_SendToken to use
                req.userId = user.id;
                
                // Call SA_SendToken with no parameters
                const result = await SA_SendToken();
                
                if (result.success) {
                    res.json({
                        success: true,
                        message: 'Login successful',
                        redirectUrl: '/dashboard'
                    });
                } else {
                    res.status(500).json({ error: result.error });
                }
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Login failed' });
        }
    });
});

// 3. PROTECTED ROUTES - Using middleware (automatic)
app.get('/dashboard', requireAuth(), (req, res) => {
    // req.user is automatically available
    res.render('dashboard', { user: req.user });
});

// 4. MANUAL VERIFICATION - Call SA_ReceiveToken directly
app.get('/api/user/profile', async (req, res) => {
    requestContext.run({ req, res }, async () => {
        const result = await SA_ReceiveToken();
        
        if (result.success) {
            // User is authenticated, req.user is now available
            const profile = await getUserProfile(req.user.userId);
            res.json(profile);
        }
        // Error already handled by SA_ReceiveToken
    });
});

// 5. LOGOUT - No parameters needed
app.post('/logout', requireAuth(), async (req, res) => {
    requestContext.run({ req, res }, async () => {
        const result = await SA_ClearToken();
        res.json(result);
    });
});

// 6. SERVER START
app.listen(3000, () => {
    console.log('Server running on port 3000');
});
*/