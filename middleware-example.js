/**
 * Middleware Example
 * Examples of middleware for Swayfy authorization
 */

const fetch = require('node-fetch'); // or axios

/**
 * Basic authorization middleware
 */
const basicAuth = (config) => {
    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];

            if (!token || !accountId || !username) {
                return res.status(401).json({
                    success: false,
                    message: 'Missing authorization data'
                });
            }

            // Verify token with Swayfy
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid token'
                });
            }

            req.user = { username, accountId, token };
            next();
        } catch (error) {
            console.error('Auth middleware error:', error);
            res.status(500).json({
                success: false,
                message: 'Authorization error'
            });
        }
    };
};

/**
 * Middleware with token caching
 */
const cachedAuth = (config) => {
    const tokenCache = new Map();
    const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];

            if (!token || !accountId || !username) {
                return res.status(401).json({
                    success: false,
                    message: 'Missing authorization data'
                });
            }

            const cacheKey = `${token}:${accountId}`;
            const cached = tokenCache.get(cacheKey);

            // Check cache
            if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
                req.user = { username, accountId, token };
                return next();
            }

            // Verify token with Swayfy
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                tokenCache.delete(cacheKey);
                return res.status(401).json({
                    success: false,
                    message: 'Invalid token'
                });
            }

            // Store in cache
            tokenCache.set(cacheKey, {
                valid: true,
                timestamp: Date.now()
            });

            req.user = { username, accountId, token };
            next();
        } catch (error) {
            console.error('Cached auth middleware error:', error);
            res.status(500).json({
                success: false,
                message: 'Authorization error'
            });
        }
    };
};

/**
 * Middleware with role-based access control
 */
const roleBasedAuth = (config, requiredRoles = []) => {
    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];

            if (!token || !accountId || !username) {
                return res.status(401).json({
                    success: false,
                    message: 'Missing authorization data'
                });
            }

            // Check if user is allowed
            if (!config.allowedUsers.includes(username)) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            // Check roles (if required)
            if (requiredRoles.length > 0) {
                const userRoles = config.userRoles[username] || [];
                const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));
                
                if (!hasRequiredRole) {
                    return res.status(403).json({
                        success: false,
                        message: 'Insufficient permissions'
                    });
                }
            }

            // Verify token
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid token'
                });
            }

            req.user = { 
                username, 
                accountId, 
                token,
                roles: config.userRoles[username] || []
            };
            next();
        } catch (error) {
            console.error('Role-based auth middleware error:', error);
            res.status(500).json({
                success: false,
                message: 'Authorization error'
            });
        }
    };
};

/**
 * Middleware with rate limiting
 */
const rateLimitedAuth = (config, maxRequests = 100, windowMs = 60000) => {
    const requestCounts = new Map();

    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];

            if (!token || !accountId || !username) {
                return res.status(401).json({
                    success: false,
                    message: 'Missing authorization data'
                });
            }

            // Rate limiting
            const now = Date.now();
            const userKey = `${username}:${accountId}`;
            const userRequests = requestCounts.get(userKey) || { count: 0, resetTime: now + windowMs };

            if (now > userRequests.resetTime) {
                userRequests.count = 0;
                userRequests.resetTime = now + windowMs;
            }

            if (userRequests.count >= maxRequests) {
                return res.status(429).json({
                    success: false,
                    message: 'Too many requests'
                });
            }

            userRequests.count++;
            requestCounts.set(userKey, userRequests);

            // Verify token
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid token'
                });
            }

            req.user = { username, accountId, token };
            next();
        } catch (error) {
            console.error('Rate limited auth middleware error:', error);
            res.status(500).json({
                success: false,
                message: 'Authorization error'
            });
        }
    };
};

/**
 * Middleware with logging
 */
const loggedAuth = (config) => {
    return async (req, res, next) => {
        const startTime = Date.now();
        
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];
            const ip = req.ip || req.connection.remoteAddress;

            console.log(`[AUTH] ${new Date().toISOString()} - ${ip} - ${username} - ${req.method} ${req.path}`);

            if (!token || !accountId || !username) {
                console.log(`[AUTH] Missing authorization data - ${ip}`);
                return res.status(401).json({
                    success: false,
                    message: 'Missing authorization data'
                });
            }

            // Verify token
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                console.log(`[AUTH] Invalid token - ${username} - ${ip}`);
                return res.status(401).json({
                    success: false,
                    message: 'Invalid token'
                });
            }

            const duration = Date.now() - startTime;
            console.log(`[AUTH] Success - ${username} - ${ip} - ${duration}ms`);

            req.user = { username, accountId, token };
            next();
        } catch (error) {
            const duration = Date.now() - startTime;
            console.error(`[AUTH] Error - ${duration}ms:`, error);
            res.status(500).json({
                success: false,
                message: 'Authorization error'
            });
        }
    };
};

/**
 * Optional authorization middleware
 */
const optionalAuth = (config) => {
    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];

            // If no auth data, continue without user
            if (!token || !accountId || !username) {
                req.user = null;
                return next();
            }

            // Verify token
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (result.success && result.valid) {
                req.user = { username, accountId, token };
            } else {
                req.user = null;
            }

            next();
        } catch (error) {
            console.error('Optional auth middleware error:', error);
            req.user = null;
            next();
        }
    };
};

module.exports = {
    basicAuth,
    cachedAuth,
    roleBasedAuth,
    rateLimitedAuth,
    loggedAuth,
    optionalAuth
};

/**
 * Usage example:
 * 
 * const { basicAuth, roleBasedAuth } = require('./middleware-example');
 * 
 * const config = {
 *   swayfy: { apiUrl: 'https://swayfy.xyz' },
 *   allowedUsers: ['admin', 'user'],
 *   userRoles: {
 *     'admin': ['read', 'write', 'delete'],
 *     'user': ['read']
 *   }
 * };
 * 
 * // Basic authorization
 * app.use('/api/protected', basicAuth(config));
 * 
 * // Role-based authorization
 * app.use('/api/admin', roleBasedAuth(config, ['write', 'delete']));
 */
