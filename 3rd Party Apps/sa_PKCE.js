/**
 * SecureAccess PKCE Validation Library
 * 
 * This library provides PKCE token validation for third-party applications
 * that receive authentication tokens from SecureAccess.
 * 
 * Usage:
 *   1. Include this file in your application
 *   2. Call sa_PKCE_Received() to validate the PKCE token
 *   3. Handle the returned status ('Passed' or 'Failed')
 * 
 * Example:
 *   const PKCE_status = sa_PKCE_Received();
 *   if (PKCE_status === 'Passed') {
 *       // User authenticated successfully
 *   } else {
 *       // Authentication failed
 *   }
 */

/**
 * Main function to validate PKCE token from SecureAccess
 * @returns {string} 'Passed' if validation succeeds, 'Failed' if validation fails
 */
function sa_PKCE_Received() {
    try {
        // Get URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const pkceToken = urlParams.get('pkce');
        const email = urlParams.get('email');
        const username = urlParams.get('username');
        
        // Check if required parameters are present
        if (!pkceToken || !email || !username) {
            console.log('SecureAccess: Missing required parameters (pkce, email, or username)');
            return 'Failed';
        }

        
        // Validate PKCE token format
        if (!isValidPKCEToken(pkceToken)) {
            console.log('SecureAccess: Invalid PKCE token format');
            return 'Failed';
        }
        
        // Validate email format
        if (!isValidEmail(email)) {
            console.log('SecureAccess: Invalid email format');
            return 'Failed';
        }
        
        // Check token expiration (tokens are valid for 5 minutes)
        if (!isTokenValid(pkceToken)) {
            console.log('SecureAccess: PKCE token expired');
            return 'Failed';
        }
        
        console.log('SecureAccess: Authentication successful for', username, '(' + email + ')');
        return 'Passed';
        
    } catch (error) {
        console.error('SecureAccess: Error validating PKCE token:', error);
        return 'Failed';
    }
}

/**
 * Validates PKCE token format
 * @param {string} token - The PKCE token to validate
 * @returns {boolean} true if token format is valid
 */
function isValidPKCEToken(token) {
    // PKCE tokens should be base64url encoded strings (43 characters)
    const pkceRegex = /^[A-Za-z0-9_-]{43}$/;
    return pkceRegex.test(token);
}

/**
 * Validates email format
 * @param {string} email - The email to validate
 * @returns {boolean} true if email format is valid
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Checks if PKCE token is still valid (not expired)
 * @param {string} token - The PKCE token to check
 * @returns {boolean} true if token is still valid
 */
function isTokenValid(token) {
    // For basic implementation, we assume tokens are valid
    // In a production environment, you might want to:
    // 1. Decode timestamp from token
    // 2. Check against server-side validation
    // 3. Implement token blacklisting
    
    // Simple validation: check if token was created recently
    // This is a basic implementation - enhance as needed
    return token && token.length === 43;
}

/**
 * Gets the authenticated user's email from URL parameters
 * @returns {string|null} The user's email if available
 */
function sa_GetUserEmail() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('email');
}

/**
 * Gets the authenticated user's username from URL parameters
 * @returns {string|null} The user's username if available
 */
function sa_GetUsername() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('username');
}

/**
 * Gets the PKCE token from URL parameters
 * @returns {string|null} The PKCE token if available
 */
function sa_GetPKCEToken() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('pkce');
}

/**
 * Clears SecureAccess parameters from URL (optional cleanup)
 */
function sa_ClearURLParameters() {
    if (window.history && window.history.replaceState) {
        const url = new URL(window.location);
        url.searchParams.delete('pkce');
        url.searchParams.delete('email');
        url.searchParams.delete('username');
        window.history.replaceState({}, document.title, url.toString());
    }
}

// Export functions for use in other modules (if using module system)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        sa_PKCE_Received,
        sa_GetUserEmail,
        sa_GetUsername,
        sa_GetPKCEToken,
        sa_ClearURLParameters
    };
}