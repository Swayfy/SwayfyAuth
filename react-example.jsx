/**
 * React Example
 * Swayfy authorization implementation in React
 */

import React, { createContext, useContext, useState, useEffect } from 'react';

// Configuration
const SWAYFY_CONFIG = {
    apiUrl: 'https://swayfy.xyz',
    redirectUrl: window.location.origin + '/auth/callback',
    confirmationToken: 'my_react_app_token'
};

/**
 * Authorization context
 */
const AuthContext = createContext();

/**
 * Hook for using authorization
 */
export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within AuthProvider');
    }
    return context;
};

/**
 * Authorization provider
 */
export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(localStorage.getItem('swayfy_token'));
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Check auth status on load
    useEffect(() => {
        checkAuthStatus();
    }, []);

    // Handle callback URL
    useEffect(() => {
        if (window.location.pathname === '/auth/callback') {
            handleCallback();
        }
    }, []);

    /**
     * Checks authorization status
     */
    const checkAuthStatus = async () => {
        const storedToken = localStorage.getItem('swayfy_token');
        const storedAccountId = localStorage.getItem('swayfy_account_id');
        const storedUsername = localStorage.getItem('swayfy_username');

        if (storedToken && storedAccountId && storedUsername) {
            try {
                const isValid = await verifyToken(storedToken, storedAccountId);
                if (isValid) {
                    setUser({
                        username: storedUsername,
                        accountId: storedAccountId
                    });
                    setToken(storedToken);
                } else {
                    logout();
                }
            } catch (error) {
                console.error('Token verification error:', error);
                logout();
            }
        }
        setLoading(false);
    };

    /**
     * Generates login link and redirects
     */
    const login = async () => {
        try {
            setLoading(true);
            setError(null);

            const response = await fetch(`${SWAYFY_CONFIG.apiUrl}/api/auth/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: 'login',
                    redirectUrl: SWAYFY_CONFIG.redirectUrl,
                    confirmationToken: SWAYFY_CONFIG.confirmationToken
                })
            });

            const data = await response.json();

            if (data.success) {
                window.location.href = data.url;
            } else {
                throw new Error('Failed to generate login link');
            }
        } catch (error) {
            setError(error.message);
            setLoading(false);
        }
    };

    /**
     * Handles callback after returning from Swayfy
     */
    const handleCallback = async () => {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const accountId = urlParams.get('id');
        const confirm = urlParams.get('confirm');

        if (code && accountId && confirm === SWAYFY_CONFIG.confirmationToken) {
            try {
                setLoading(true);
                const tokenData = await exchangeToken(code, accountId);

                // Store data
                localStorage.setItem('swayfy_token', tokenData.token);
                localStorage.setItem('swayfy_account_id', tokenData.user.accountId);
                localStorage.setItem('swayfy_username', tokenData.user.username);

                setToken(tokenData.token);
                setUser(tokenData.user);

                // Clear URL
                window.history.replaceState({}, document.title, '/dashboard');
            } catch (error) {
                setError(error.message);
                window.history.replaceState({}, document.title, '/login');
            } finally {
                setLoading(false);
            }
        } else {
            setError('Invalid authorization parameters');
            window.history.replaceState({}, document.title, '/login');
            setLoading(false);
        }
    };

    /**
     * Exchanges code for token
     */
    const exchangeToken = async (code, accountId) => {
        const response = await fetch(`${SWAYFY_CONFIG.apiUrl}/api/exchangeToken`, {
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
    };

    /**
     * Verifies token
     */
    const verifyToken = async (token, accountId) => {
        const response = await fetch(`${SWAYFY_CONFIG.apiUrl}/api/verifyToken`, {
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
    };

    /**
     * Logs out user
     */
    const logout = () => {
        localStorage.removeItem('swayfy_token');
        localStorage.removeItem('swayfy_account_id');
        localStorage.removeItem('swayfy_username');
        setUser(null);
        setToken(null);
        setError(null);
    };

    /**
     * Makes authenticated request
     */
    const authenticatedRequest = async (url, options = {}) => {
        if (!token || !user) {
            throw new Error('User is not authenticated');
        }

        const headers = {
            'Authorization': `Bearer ${token}`,
            'X-Account-ID': user.accountId,
            'X-Username': user.username,
            'Content-Type': 'application/json',
            ...options.headers
        };

        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            logout();
            throw new Error('Session expired');
        }

        return response;
    };

    const value = {
        user,
        token,
        loading,
        error,
        login,
        logout,
        authenticatedRequest,
        isAuthenticated: !!user
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};

/**
 * Route protection component
 */
export const ProtectedRoute = ({ children, fallback = null }) => {
    const { isAuthenticated, loading } = useAuth();

    if (loading) {
        return <div>Loading...</div>;
    }

    if (!isAuthenticated) {
        return fallback || <LoginPage />;
    }

    return children;
};

/**
 * Login page component
 */
const LoginPage = () => {
    const { login, loading, error } = useAuth();

    return (
        <div className="login-page">
            <div className="login-container">
                <h1>Login</h1>
                <p>Log in using your Swayfy account</p>
                
                {error && (
                    <div className="error-message">
                        {error}
                    </div>
                )}
                
                <button 
                    onClick={login} 
                    disabled={loading}
                    className="login-button"
                >
                    {loading ? 'Loading...' : 'Login with Swayfy'}
                </button>
            </div>
        </div>
    );
};

/**
 * Dashboard component
 */
const Dashboard = () => {
    const { user, logout, authenticatedRequest } = useAuth();
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);

    const fetchData = async () => {
        try {
            setLoading(true);
            const response = await authenticatedRequest('/api/protected/data');
            const result = await response.json();
            setData(result.data);
        } catch (error) {
            console.error('Error fetching data:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    return (
        <div className="dashboard">
            <header className="dashboard-header">
                <h1>Dashboard</h1>
                <div className="user-info">
                    <span>Welcome, {user.username}!</span>
                    <button onClick={logout}>Logout</button>
                </div>
            </header>
            
            <main className="dashboard-content">
                {loading ? (
                    <div>Loading data...</div>
                ) : data ? (
                    <div>
                        <h2>Your data:</h2>
                        <pre>{JSON.stringify(data, null, 2)}</pre>
                    </div>
                ) : (
                    <div>No data</div>
                )}
                
                <button onClick={fetchData}>Refresh data</button>
            </main>
        </div>
    );
};

/**
 * Main application component
 */
const App = () => {
    return (
        <AuthProvider>
            <div className="app">
                <ProtectedRoute>
                    <Dashboard />
                </ProtectedRoute>
            </div>
        </AuthProvider>
    );
};

/**
 * Hook for authenticated requests
 */
export const useAuthenticatedRequest = () => {
    const { authenticatedRequest } = useAuth();
    
    return {
        get: (url) => authenticatedRequest(url),
        post: (url, data) => authenticatedRequest(url, {
            method: 'POST',
            body: JSON.stringify(data)
        }),
        put: (url, data) => authenticatedRequest(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        }),
        delete: (url) => authenticatedRequest(url, {
            method: 'DELETE'
        })
    };
};

/**
 * Example usage in component
 */
const ExampleComponent = () => {
    const { user, isAuthenticated } = useAuth();
    const api = useAuthenticatedRequest();
    const [posts, setPosts] = useState([]);

    const fetchPosts = async () => {
        try {
            const response = await api.get('/api/posts');
            const data = await response.json();
            setPosts(data);
        } catch (error) {
            console.error('Error fetching posts:', error);
        }
    };

    const createPost = async (postData) => {
        try {
            const response = await api.post('/api/posts', postData);
            const newPost = await response.json();
            setPosts([...posts, newPost]);
        } catch (error) {
            console.error('Error creating post:', error);
        }
    };

    if (!isAuthenticated) {
        return <div>You must be logged in</div>;
    }

    return (
        <div>
            <h2>Welcome {user.username}!</h2>
            <button onClick={fetchPosts}>Fetch posts</button>
            {/* Rest of component */}
        </div>
    );
};

export default App;

/**
 * CSS for example (optional)
 */
const styles = `
.login-page {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    background: #f5f5f5;
}

.login-container {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    text-align: center;
    max-width: 400px;
    width: 100%;
}

.login-button {
    background: #0066ff;
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 16px;
    margin-top: 1rem;
    width: 100%;
}

.login-button:hover {
    background: #0052cc;
}

.login-button:disabled {
    background: #ccc;
    cursor: not-allowed;
}

.error-message {
    background: #fee;
    color: #c33;
    padding: 12px;
    border-radius: 4px;
    margin: 1rem 0;
    border: 1px solid #fcc;
}

.dashboard {
    min-height: 100vh;
    background: #f8f9fa;
}

.dashboard-header {
    background: white;
    padding: 1rem 2rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.dashboard-content {
    padding: 2rem;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 1rem;
}
`;
