/**
 * PKCE JWT Handler for Third-Party Applications
 * Extracts user data from PKCE token and creates JWT token
 */

class PKCEJWTHandler {
    constructor(secureAccessApiUrl) {
        this.apiUrl = secureAccessApiUrl;
    }

    /**
     * Extract user data from PKCE session and create JWT token
     */
    async processAuth() {
        const urlParams = new URLSearchParams(window.location.search);
        const sessionId = urlParams.get('session_id');
        
        if (!sessionId) {
            throw new Error('No PKCE session ID found');
        }

        try {
            // Validate PKCE session with SecureAccess server
            const response = await fetch(`${this.apiUrl}/api/pkce/session/${sessionId}`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                throw new Error('Invalid PKCE session');
            }

            const sessionData = await response.json();
            const userData = sessionData.userData;

            if (!userData) {
                throw new Error('No user data in PKCE session');
            }

            // Create JWT token with user data
            const jwtToken = this.createJWT(userData);
            
            // Store JWT token
            localStorage.setItem('authToken', jwtToken);
            
            return {
                username: userData.username,
                email: userData.email,
                token: jwtToken
            };

        } catch (error) {
            console.error('PKCE authentication failed:', error);
            throw error;
        }
    }

    /**
     * Create simple JWT token (client-side only, for demo purposes)
     */
    createJWT(userData) {
        const header = { alg: 'none', typ: 'JWT' };
        const payload = {
            username: userData.username,
            email: userData.email,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
        };

        const encodedHeader = btoa(JSON.stringify(header));
        const encodedPayload = btoa(JSON.stringify(payload));
        
        return `${encodedHeader}.${encodedPayload}.`;
    }

    /**
     * Get user data from URL parameters (fallback for non-PKCE apps)
     */
    getUserFromParams() {
        const urlParams = new URLSearchParams(window.location.search);
        return {
            username: urlParams.get('username'),
            email: urlParams.get('email')
        };
    }

    /**
     * Initialize authentication - tries PKCE first, falls back to URL params
     */
    async init() {
        try {
            // Try PKCE authentication first
            return await this.processAuth();
        } catch (error) {
            // Fallback to URL parameters
            const userData = this.getUserFromParams();
            if (userData.username || userData.email) {
                const jwtToken = this.createJWT(userData);
                localStorage.setItem('authToken', jwtToken);
                return { ...userData, token: jwtToken };
            }
            throw new Error('No authentication data found');
        }
    }
}

// Usage example:
// const authHandler = new PKCEJWTHandler('http://localhost:3000');
// authHandler.init().then(userData => {
//     console.log('Authenticated user:', userData);
// }).catch(error => {
//     console.error('Authentication failed:', error);
// });

window.PKCEJWTHandler = PKCEJWTHandler;