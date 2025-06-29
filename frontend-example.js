/**
 * Frontend Example - Vanilla JavaScript
 * Implementacja autoryzacji Swayfy po stronie klienta
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
        // Sprawdź czy jesteśmy na stronie callback
        if (window.location.pathname === '/auth/callback') {
            this.handleCallback();
        }
        
        // Sprawdź czy użytkownik jest zalogowany
        if (this.token && this.accountId) {
            this.verifyToken();
        }
    }

    /**
     * Generuje link logowania i przekierowuje użytkownika
     */
    async login() {
        try {
            this.showLoading('Generowanie linku logowania...');
            
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
                // Przekieruj do Swayfy
                window.location.href = data.url;
            } else {
                throw new Error('Nie udało się wygenerować linku logowania');
            }
        } catch (error) {
            this.showError('Błąd logowania: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }

    /**
     * Obsługuje callback po powrocie z Swayfy
     */
    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const accountId = urlParams.get('id');
        const confirm = urlParams.get('confirm');

        if (code && accountId && confirm === this.config.confirmationToken) {
            try {
                this.showLoading('Finalizowanie logowania...');
                
                const tokenData = await this.exchangeToken(code, accountId);
                
                // Zapisz dane użytkownika
                this.token = tokenData.token;
                this.accountId = tokenData.user.accountId;
                this.username = tokenData.user.username;
                
                localStorage.setItem('swayfy_token', this.token);
                localStorage.setItem('swayfy_account_id', this.accountId);
                localStorage.setItem('swayfy_username', this.username);
                
                // Wyczyść URL i przekieruj
                window.history.replaceState({}, document.title, '/dashboard');
                this.onLoginSuccess(tokenData.user);
                
            } catch (error) {
                this.showError('Błąd podczas finalizacji logowania: ' + error.message);
                window.history.replaceState({}, document.title, '/login');
            } finally {
                this.hideLoading();
            }
        } else {
            this.showError('Nieprawidłowe parametry autoryzacji');
            window.history.replaceState({}, document.title, '/login');
        }
    }

    /**
     * Wymienia kod autoryzacyjny na token dostępu
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
            throw new Error(data.message || 'Wymiana tokena nie powiodła się');
        }
    }

    /**
     * Weryfikuje ważność tokena
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
            console.error('Błąd weryfikacji tokena:', error);
            this.logout();
            return false;
        }
    }

    /**
     * Wylogowuje użytkownika
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
     * Sprawdza czy użytkownik jest zalogowany
     */
    isAuthenticated() {
        return !!(this.token && this.accountId);
    }

    /**
     * Pobiera dane użytkownika
     */
    getUser() {
        return {
            username: this.username,
            accountId: this.accountId,
            token: this.token
        };
    }

    /**
     * Wykonuje autoryzowane żądanie do API
     */
    async authenticatedRequest(url, options = {}) {
        if (!this.isAuthenticated()) {
            throw new Error('Użytkownik nie jest zalogowany');
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
            // Token wygasł
            this.logout();
            throw new Error('Sesja wygasła');
        }

        return response;
    }

    // Metody UI (do nadpisania)
    showLoading(message) {
        console.log('Loading:', message);
        // Implementuj własny loader
    }

    hideLoading() {
        console.log('Loading finished');
        // Ukryj loader
    }

    showError(message) {
        console.error('Error:', message);
        alert(message); // Zastąp własnym systemem powiadomień
    }

    onLoginSuccess(user) {
        console.log('Login successful:', user);
        // Implementuj logikę po udanym logowaniu
    }

    onTokenValid() {
        console.log('Token is valid');
        // Implementuj logikę gdy token jest ważny
    }

    onLogout() {
        console.log('User logged out');
        window.location.href = '/login';
    }
}

// Przykład użycia
const auth = new SwayfyAuth({
    confirmationToken: 'my_unique_app_token',
    redirectUrl: 'https://moja-aplikacja.com/auth/callback'
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
    
    // Sprawdź status autoryzacji przy ładowaniu strony
    if (auth.isAuthenticated()) {
        // Pokaż interfejs zalogowanego użytkownika
        showAuthenticatedUI(auth.getUser());
    } else {
        // Pokaż formularz logowania
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

// Przykład autoryzowanego żądania
async function fetchUserData() {
    try {
        const response = await auth.authenticatedRequest('/api/user/profile');
        const userData = await response.json();
        console.log('User data:', userData);
    } catch (error) {
        console.error('Błąd pobierania danych:', error);
    }
}