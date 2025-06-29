/**
 * Frontend Example - Vanilla JavaScript
 * Swayfy authorization implementation for client-side
 */

class SwayfyAuth {
    constructor(config) {
        this.config = {
            apiUrl: 'https://swayfy.xyz',
            redirectUrl: window.location.origin + '/auth/callback',
            confirmationToken: 'my_app_token',
            ...config
        };
        
        this.token = localStorage.getItem('swayfy_token');
        this.accountId = localStorage.getItem('swayfy_account_id');
        this.username = localStorage.getItem('swayfy_username');
        
        this.init();
    }

    init() {
        // Check if we're on the callback page
        if (window.location.pathname === '/auth/callback') {
            this.handleCallback();
        }
        
        // Check if user is logged in
        if (this.token && this.accountId) {
            this.verifyToken();
        }
    }

    /**
     * Generates login link and redirects user
     */
    async login() {
        try {
            this.showLoading('Generating login link...');
            
            const response = await fetch(`${this.config.apiUrl}/api/auth/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: 'login',
                    redirectUrl: this.config.redirectUrl,
                    confirmationToken: this.config.confirmationToken
                })
            });

            const data = await response.json();
            
            if (data.success) {
                // Redirect to Swayfy
                window.location.href = data.url;
            } else {
                throw new Error('Failed to generate login link');
            }
        } catch (error) {
            this.showError('Login error: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }

    /**
     * Handles callback after returning from Swayfy
     */
    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const accountId = urlParams.get('id');
        const confirm = urlParams.get('confirm');

        if (code && accountId && confirm === this.config.confirmationToken) {
            try {
                this.showLoading('Finalizing login...');
                
                const tokenData = await this.exchangeToken(code, accountId);
                
                // Store user data
                this.token = tokenData.token;
                this.accountId = tokenData.user.accountId;
                this.username = tokenData.user.username;
                
                localStorage.setItem('swayfy_token', this.token);
                localStorage.setItem('swayfy_account_id', this.accountId);
                localStorage.setItem('swayfy_username', this.username);
                
                // Clear URL and redirect
                window.history.replaceState({}, document.title, '/dashboard');
                this.onLoginSuccess(tokenData.user);
                
            } catch (error) {
                this.showError('Error finalizing login: ' + error.message);
                window.history.replaceState({}, document.title, '/login');
            } finally {
                this.hideLoading();
            }
        } else {
            this.showError('Invalid authorization parameters');
            window.history.replaceState({}, document.title, '/login');
        }
    }

    /**
     * Exchanges authorization code for access token
     */
    async exchangeToken(code, accountId) {
        const response = await fetch(`${this.config.apiUrl}/api/exchangeToken`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                accountId: accountId
            })
        });

        const data = await response.json();
        
        if (data.success) {
            return data;
        } else {
            throw new Error(data.message || 'Token exchange failed');
        }
    }

    /**
     * Verifies token validity
     */
    async verifyToken() {
        if (!this.token || !this.accountId) {
            this.logout();
            return false;
        }

        try {
            const response = await fetch(`${this.config.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    token: this.token,
                    accountId: this.accountId
                })
            });

            const data = await response.json();
            
            if (data.success && data.valid) {
                this.onTokenValid();
                return true;
            } else {
                this.logout();
                return false;
            }
        } catch (error) {
            console.error('Token verification error:', error);
            this.logout();
            return false;
        }
    }

    /**
     * Logs out the user
     */
    logout() {
        this.token = null;
        this.accountId = null;
        this.username = null;
        
        localStorage.removeItem('swayfy_token');
        localStorage.removeItem('swayfy_account_id');
        localStorage.removeItem('swayfy_username');
        
        this.onLogout();
    }

    /**
     * Checks if user is authenticated
     */
    isAuthenticated() {
        return !!(this.token && this.accountId);
    }

    /**
     * Gets user data
     */
    getUser() {
        return {
            username: this.username,
            accountId: this.accountId,
            token: this.token
        };
    }

    /**
     * Makes authenticated request to API
     */
    async authenticatedRequest(url, options = {}) {
        if (!this.isAuthenticated()) {
            throw new Error('User is not authenticated');
        }

        const headers = {
            'Authorization': `Bearer ${this.token}`,
            'X-Account-ID': this.accountId,
            'Content-Type': 'application/json',
            ...options.headers
        };

        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            // Token expired
            this.logout();
            throw new Error('Session expired');
        }

        return response;
    }

    // UI methods (to be overridden)
    showLoading(message) {
        console.log('Loading:', message);
        // Implement your own loader
    }

    hideLoading() {
        console.log('Loading finished');
        // Hide loader
    }

    showError(message) {
        console.error('Error:', message);
        alert(message); // Replace with your own notification system
    }

    onLoginSuccess(user) {
        console.log('Login successful:', user);
        // Implement logic after successful login
    }

    onTokenValid() {
        console.log('Token is valid');
        // Implement logic when token is valid
    }

    onLogout() {
        console.log('User logged out');
        window.location.href = '/login';
    }
}

// Usage example
const auth = new SwayfyAuth({
    confirmationToken: 'my_unique_app_token',
    redirectUrl: 'https://my-app.com/auth/callback'
});

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const loginBtn = document.getElementById('loginBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    
    if (loginBtn) {
        loginBtn.addEventListener('click', () => auth.login());
    }
    
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => auth.logout());
    }
    
    // Check auth status on page load
    if (auth.isAuthenticated()) {
        // Show authenticated user interface
        showAuthenticatedUI(auth.getUser());
    } else {
        // Show login form
        showLoginUI();
    }
});

function showAuthenticatedUI(user) {
    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('dashboardSection').style.display = 'block';
    document.getElementById('username').textContent = user.username;
}

function showLoginUI() {
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('dashboardSection').style.display = 'none';
}

// Example authenticated request
async function fetchUserData() {
    try {
        const response = await auth.authenticatedRequest('/api/user/profile');
        const userData = await response.json();
        console.log('User data:', userData);
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}
