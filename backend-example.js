/**
 * Backend Example - Node.js/Express
 * Implementacja autoryzacji Swayfy po stronie serwera
 */

const express = require('express');
const cors = require('cors');
const app = express();

// Konfiguracja
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
 * Klasa do zarządzania autoryzacją Swayfy
 */
class SwayfyAuthManager {
    constructor(config) {
        this.config = config;
    }

    /**
     * Generuje link autoryzacyjny
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
                throw new Error('Nie udało się wygenerować linku autoryzacyjnego');
            }
        } catch (error) {
            console.error('Błąd generowania linku:', error);
            throw error;
        }
    }

    /**
     * Wymienia kod autoryzacyjny na token dostępu
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
                throw new Error(data.message || 'Wymiana tokena nie powiodła się');
            }
        } catch (error) {
            console.error('Błąd wymiany tokena:', error);
            throw error;
        }
    }

    /**
     * Weryfikuje ważność tokena
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
            console.error('Błąd weryfikacji tokena:', error);
            return false;
        }
    }

    /**
     * Sprawdza czy użytkownik ma uprawnienia
     */
    isUserAllowed(username) {
        return this.config.allowedUsers.includes(username);
    }
}

// Inicjalizacja managera autoryzacji
const authManager = new SwayfyAuthManager(config);

/**
 * Middleware do sprawdzania autoryzacji
 */
const requireAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const accountId = req.headers['x-account-id'];
        const username = req.headers['x-username'];

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: 'Brak tokena autoryzacji'
            });
        }

        const token = authHeader.substring(7); // Usuń "Bearer "

        if (!token || !accountId || !username) {
            return res.status(401).json({
                success: false,
                message: 'Niepełne dane autoryzacji'
            });
        }

        // Sprawdź uprawnienia użytkownika
        if (!authManager.isUserAllowed(username)) {
            return res.status(403).json({
                success: false,
                message: 'Brak uprawnień dostępu'
            });
        }

        // Weryfikuj token
        const isValid = await authManager.verifyToken(token, accountId);
        
        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Nieprawidłowy lub wygasły token'
            });
        }

        // Dodaj dane użytkownika do requesta
        req.user = {
            username: username,
            accountId: accountId,
            token: token
        };

        next();
    } catch (error) {
        console.error('Błąd middleware autoryzacji:', error);
        res.status(500).json({
            success: false,
            message: 'Błąd weryfikacji autoryzacji'
        });
    }
};

/**
 * ROUTES
 */

// Generowanie linku logowania
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
            message: 'Błąd generowania linku autoryzacyjnego'
        });
    }
});

// Obsługa callback po autoryzacji
app.post('/api/auth/callback', async (req, res) => {
    try {
        const { code, accountId, confirm } = req.body;

        // Sprawdź token potwierdzenia
        if (confirm !== config.swayfy.confirmationToken) {
            return res.status(400).json({
                success: false,
                message: 'Nieprawidłowy token potwierdzenia'
            });
        }

        if (!code || !accountId) {
            return res.status(400).json({
                success: false,
                message: 'Brak wymaganych parametrów'
            });
        }

        // Wymień kod na token
        const tokenData = await authManager.exchangeCodeForToken(code, accountId);

        // Sprawdź uprawnienia użytkownika
        if (!authManager.isUserAllowed(tokenData.user.username)) {
            return res.status(403).json({
                success: false,
                message: 'Brak uprawnień dostępu do aplikacji'
            });
        }

        res.json({
            success: true,
            token: tokenData.token,
            user: tokenData.user
        });
    } catch (error) {
        console.error('Błąd callback:', error);
        res.status(500).json({
            success: false,
            message: 'Błąd podczas autoryzacji'
        });
    }
});

// Weryfikacja tokena
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { token, accountId, username } = req.body;

        if (!token || !accountId || !username) {
            return res.status(400).json({
                success: false,
                message: 'Brak wymaganych danych'
            });
        }

        // Sprawdź uprawnienia
        if (!authManager.isUserAllowed(username)) {
            return res.status(403).json({
                success: false,
                authorized: false,
                message: 'Brak uprawnień'
            });
        }

        // Weryfikuj token
        const isValid = await authManager.verifyToken(token, accountId);

        res.json({
            success: true,
            valid: isValid,
            authorized: isValid
        });
    } catch (error) {
        console.error('Błąd weryfikacji:', error);
        res.status(500).json({
            success: false,
            message: 'Błąd weryfikacji tokena'
        });
    }
});

// Przykład chronionego endpointu
app.get('/api/protected/profile', requireAuth, (req, res) => {
    res.json({
        success: true,
        user: req.user,
        message: 'Dostęp do chronionego zasobu'
    });
});

// Przykład chronionego endpointu z danymi
app.get('/api/protected/data', requireAuth, async (req, res) => {
    try {
        // Tutaj możesz pobrać dane specyficzne dla użytkownika
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
        console.error('Błąd pobierania danych:', error);
        res.status(500).json({
            success: false,
            message: 'Błąd pobierania danych użytkownika'
        });
    }
});

// Endpoint do sprawdzania statusu serwera
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

// Obsługa błędów
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    
    res.status(500).json({
        success: false,
        message: 'Wewnętrzny błąd serwera'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint nie został znaleziony'
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Serwer uruchomiony na porcie ${PORT}`);
    console.log(`🔗 Swayfy API: ${config.swayfy.apiUrl}`);
    console.log(`📍 Redirect URL: ${config.swayfy.redirectUrl}`);
    console.log(`👥 Dozwoleni użytkownicy: ${config.allowedUsers.join(', ')}`);
});

module.exports = app;