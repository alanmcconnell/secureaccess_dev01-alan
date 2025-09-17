// Shared functions for secure access application

// CSRF token management
const CSRFManager = {
    token: null,
    
    async getToken() {
        if (this.token) {
            return this.token;
        }
        
        try {
            const response = await fetch('http://localhost:3000/api/csrf-token', { 
                credentials: 'include',
                method: 'GET'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            this.token = data.csrfToken;
            return this.token;
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
            return null;
        }
    },
    
    clearToken() {
        this.token = null;
    }
};

// Auth token management
const AuthManager = {
    setToken(token) {
        localStorage.setItem('authToken', token);
        this.parseAndStoreUserInfo(token);
    },

    getToken() {
        return localStorage.getItem('authToken');
    },

    clearToken() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('user_info');
    },

    parseAndStoreUserInfo(token) {
        if (!token) return null;
        try {
            // Get the payload part of the JWT (second part)
            const payload = JSON.parse(atob(token.split('.')[1]));
            const userInfo = {
                userId: payload.userId,
                username: payload.username,
                email: payload.email
            };
            localStorage.setItem('user_info', JSON.stringify(userInfo));
            return userInfo;
        } catch (e) {
            console.error('Error parsing JWT token:', e);
            return null;
        }
    },

    getUserInfo() {
        const userInfoStr = localStorage.getItem('user_info');
        if (!userInfoStr) {
            const token = this.getToken();
            if (token) {
                return this.parseAndStoreUserInfo(token);
            }
            return null;
        }
        return JSON.parse(userInfoStr);
    },

    isLoggedIn() {
        return !!this.getToken();
    }
};

// Global web page redirect function
window.SA_GoToWebPage = function(webpage) {
    window.location.href = webpage;
};

// Global function to initialize a protected page
window.SA_InitializePage = function() {
    if (!AuthManager.isLoggedIn()) {
        window.location.href = 'login_client.html';
        return false;
    }
    return true;
};

// Export for use in other scripts
window.AuthManager = AuthManager;
window.CSRFManager = CSRFManager;
