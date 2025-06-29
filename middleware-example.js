/**
 * Middleware Example
 * Przykłady middleware do autoryzacji Swayfy
 */

const fetch = require('node-fetch'); // lub axios

/**
 * Podstawowy middleware autoryzacji
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
                    message: 'Brak danych autoryzacji'
                });
            }

            // Weryfikuj token w Swayfy
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                return res.status(401).json({
                    success: false,
                    message: 'Nieprawidłowy token'
                });
            }

            req.user = { username, accountId, token };
            next();
        } catch (error) {
            console.error('Auth middleware error:', error);
            res.status(500).json({
                success: false,
                message: 'Błąd autoryzacji'
            });
        }
    };
};

/**
 * Middleware z cache tokenów
 */
const cachedAuth = (config) => {
    const tokenCache = new Map();
    const CACHE_TTL = 5 * 60 * 1000; // 5 minut

    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];

            if (!token || !accountId || !username) {
                return res.status(401).json({
                    success: false,
                    message: 'Brak danych autoryzacji'
                });
            }

            const cacheKey = `${token}:${accountId}`;
            const cached = tokenCache.get(cacheKey);

            // Sprawdź cache
            if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
                req.user = { username, accountId, token };
                return next();
            }

            // Weryfikuj token w Swayfy
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
                    message: 'Nieprawidłowy token'
                });
            }

            // Zapisz w cache
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
                message: 'Błąd autoryzacji'
            });
        }
    };
};

/**
 * Middleware z kontrolą uprawnień
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
                    message: 'Brak danych autoryzacji'
                });
            }

            // Sprawdź czy użytkownik jest dozwolony
            if (!config.allowedUsers.includes(username)) {
                return res.status(403).json({
                    success: false,
                    message: 'Brak uprawnień'
                });
            }

            // Sprawdź role (jeśli wymagane)
            if (requiredRoles.length > 0) {
                const userRoles = config.userRoles[username] || [];
                const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));
                
                if (!hasRequiredRole) {
                    return res.status(403).json({
                        success: false,
                        message: 'Niewystarczające uprawnienia'
                    });
                }
            }

            // Weryfikuj token
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                return res.status(401).json({
                    success: false,
                    message: 'Nieprawidłowy token'
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
                message: 'Błąd autoryzacji'
            });
        }
    };
};

/**
 * Middleware z rate limiting
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
                    message: 'Brak danych autoryzacji'
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
                    message: 'Zbyt wiele żądań'
                });
            }

            userRequests.count++;
            requestCounts.set(userKey, userRequests);

            // Weryfikuj token
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                return res.status(401).json({
                    success: false,
                    message: 'Nieprawidłowy token'
                });
            }

            req.user = { username, accountId, token };
            next();
        } catch (error) {
            console.error('Rate limited auth middleware error:', error);
            res.status(500).json({
                success: false,
                message: 'Błąd autoryzacji'
            });
        }
    };
};

/**
 * Middleware z logowaniem
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
                console.log(`[AUTH] Brak danych autoryzacji - ${ip}`);
                return res.status(401).json({
                    success: false,
                    message: 'Brak danych autoryzacji'
                });
            }

            // Weryfikuj token
            const response = await fetch(`${config.swayfy.apiUrl}/api/verifyToken`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, accountId })
            });

            const result = await response.json();

            if (!result.success || !result.valid) {
                console.log(`[AUTH] Nieprawidłowy token - ${username} - ${ip}`);
                return res.status(401).json({
                    success: false,
                    message: 'Nieprawidłowy token'
                });
            }

            const duration = Date.now() - startTime;
            console.log(`[AUTH] Sukces - ${username} - ${ip} - ${duration}ms`);

            req.user = { username, accountId, token };
            next();
        } catch (error) {
            const duration = Date.now() - startTime;
            console.error(`[AUTH] Błąd - ${duration}ms:`, error);
            res.status(500).json({
                success: false,
                message: 'Błąd autoryzacji'
            });
        }
    };
};

/**
 * Middleware opcjonalnej autoryzacji
 */
const optionalAuth = (config) => {
    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const accountId = req.headers['x-account-id'];
            const username = req.headers['x-username'];

            // Jeśli brak danych autoryzacji, kontynuuj bez użytkownika
            if (!token || !accountId || !username) {
                req.user = null;
                return next();
            }

            // Weryfikuj token
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
 * Przykład użycia:
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
 * // Podstawowa autoryzacja
 * app.use('/api/protected', basicAuth(config));
 * 
 * // Autoryzacja z rolami
 * app.use('/api/admin', roleBasedAuth(config, ['write', 'delete']));
 */