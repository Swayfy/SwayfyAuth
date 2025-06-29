/**
 * Backend Example - Node.js/Express
 * Swayfy authorization implementation for server-side
 */

const express = require('express');
const cors = require('cors');
const app = express();

// Configuration
const config = {
    swayfy: {
        apiUrl: 'https://swayfy.xyz',
        redirectUrl: process.env.SWAYFY_REDIRECT_URL || 'http://localhost:3000/auth/callback',
        confirmationToken: process.env.SWAYFY_CONFIRMATION_TOKEN || 'my_app_token'
    },
    allowedUsers: [
        'admin_user',
        'regular_user'
    ]
};

app.use(cors());
app.use(express.json());

/**
 * Class for managing Swayfy authorization
 */
class SwayfyAuthManager {
    constructor(config) {
        this.config = config;
    }

    /**
     * Generates authorization link
     */
    async generateAuthLink() {
        try {
            const response = await fetch(`${this.config.swayfy.apiUrl}/api/auth/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: 'login',
                    redirectUrl: this.config.swayfy.redirectUrl,
                    confirmationToken: this.config.swayfy.confirmationToken
                })
            });

            const data = await response.json();
            
            if (data.success) {
                return data.url;
            } else {
                throw new Error('Failed to generate authorization link');
            }
        } catch (error) {
            console.error('Link generation error:', error);
            throw error;
        }
    }

    /**
     * Exchanges authorization code for access token
     */
    async exchangeCodeForToken(code, accountId) {
        try {
            const response = await fetch(`${this.config.swayfy.apiUrl}/api/exchangeToken`, {
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
                return {
                    token: data.token,
                    user: data.user
                };
            } else {
                throw new Error(data.message || 'Token exchange failed');
            }
        } catch (error) {
            console.error('Token exchange error:', error);
            throw error;
        }
    }

    /**
     * Verifies token validity
     */
    async verifyToken(token, accountId) {
        try {
            const response = await fetch(`${this.config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    token: token,
                    accountId: accountId
                })
            });

            const data = await response.json();
            return data.success && data.valid;
        } catch (error) {
            console.error('Token verification error:', error);
            return false;
        }
    }

    /**
     * Checks if user has permissions
     */
    isUserAllowed(username) {
        return this.config.allowedUsers.includes(username);
    }
}

// Initialize auth manager
const authManager = new SwayfyAuthManager(config);

/**
 * Middleware for checking authorization
 */
const requireAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const accountId = req.headers['x-account-id'];
        const username = req.headers['x-username'];

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: 'Missing authorization token'
            });
        }

        const token = authHeader.substring(7); // Remove "Bearer "

        if (!token || !accountId || !username) {
            return res.status(401).json({
                success: false,
                message: 'Incomplete authorization data'
            });
        }

        // Check user permissions
        if (!authManager.isUserAllowed(username)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }

        // Verify token
        const isValid = await authManager.verifyToken(token, accountId);
        
        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }

        // Add user data to request
        req.user = {
            username: username,
            accountId: accountId,
            token: token
        };

        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({
            success: false,
            message: 'Authorization verification error'
        });
    }
};

/**
 * ROUTES
 */

// Generate login link
app.post('/api/auth/generate-link', async (req, res) => {
    try {
        const authUrl = await authManager.generateAuthLink();
        
        res.json({
            success: true,
            url: authUrl
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error generating authorization link'
        });
    }
});

// Handle callback after authorization
app.post('/api/auth/callback', async (req, res) => {
    try {
        const { code, accountId, confirm } = req.body;

        // Check confirmation token
        if (confirm !== config.swayfy.confirmationToken) {
            return res.status(400).json({
                success: false,
                message: 'Invalid confirmation token'
            });
        }

        if (!code || !accountId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameters'
            });
        }

        // Exchange code for token
        const tokenData = await authManager.exchangeCodeForToken(code, accountId);

        // Check user permissions
        if (!authManager.isUserAllowed(tokenData.user.username)) {
            return res.status(403).json({
                success: false,
                message: 'No access permissions to application'
            });
        }

        res.json({
            success: true,
            token: tokenData.token,
            user: tokenData.user
        });
    } catch (error) {
        console.error('Callback error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during authorization'
        });
    }
});

// Token verification
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { token, accountId, username } = req.body;

        if (!token || !accountId || !username) {
            return res.status(400).json({
                success: false,
                message: 'Missing required data'
            });
        }

        // Check permissions
        if (!authManager.isUserAllowed(username)) {
            return res.status(403).json({
                success: false,
                authorized: false,
                message: 'No permissions'
            });
        }

        // Verify token
        const isValid = await authManager.verifyToken(token, accountId);

        res.json({
            success: true,
            valid: isValid,
            authorized: isValid
        });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Token verification error'
        });
    }
});

// Example protected endpoint
app.get('/api/protected/profile', requireAuth, (req, res) => {
    res.json({
        success: true,
        user: req.user,
        message: 'Access to protected resource'
    });
});

// Example protected endpoint with data
app.get('/api/protected/data', requireAuth, async (req, res) => {
    try {
        // Here you can fetch user-specific data
        const userData = {
            username: req.user.username,
            accountId: req.user.accountId,
            lastLogin: new Date().toISOString(),
            permissions: ['read', 'write']
        };

        res.json({
            success: true,
            data: userData
        });
    } catch (error) {
        console.error('Data fetch error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching user data'
        });
    }
});

// Server status endpoint
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'OK',
        timestamp: new Date().toISOString(),
        swayfy: {
            apiUrl: config.swayfy.apiUrl,
            redirectUrl: config.swayfy.redirectUrl
        }
    });
});

// Error handling
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔗 Swayfy API: ${config.swayfy.apiUrl}`);
    console.log(`📍 Redirect URL: ${config.swayfy.redirectUrl}`);
    console.log(`👥 Allowed users: ${config.allowedUsers.join(', ')}`);
});

module.exports = app;
