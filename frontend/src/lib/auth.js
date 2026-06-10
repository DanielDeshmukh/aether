const ACCESS_TOKEN_KEY = 'aether_access_token';
const REFRESH_TOKEN_KEY = 'aether_refresh_token';
const AUTH_EVENT = 'aether-auth-change';

function decodeJwtPayload(token) {
  try {
    const base64 = token.split('.')[1];
    const padded = base64.replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(padded)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function isTokenExpired(token) {
  const payload = decodeJwtPayload(token);
  if (!payload || !payload.exp) return true;
  return Date.now() >= payload.exp * 1000;
}

function emitAuthChange() {
  window.dispatchEvent(new Event(AUTH_EVENT));
}

export const auth = {
  getAccessToken() {
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  },

  getRefreshToken() {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  },

  setTokens(accessToken, refreshToken) {
    localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
    if (refreshToken) {
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    }
    emitAuthChange();
  },

  clearTokens() {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    emitAuthChange();
  },

  isAuthenticated() {
    const token = this.getAccessToken();
    if (!token) return false;
    if (isTokenExpired(token)) {
      this.clearTokens();
      return false;
    }
    return true;
  },

  getUserId() {
    const token = this.getAccessToken();
    if (!token) return null;
    const payload = decodeJwtPayload(token);
    return payload?.sub || null;
  },

  getUserEmail() {
    const token = this.getAccessToken();
    if (!token) return null;
    const payload = decodeJwtPayload(token);
    return payload?.email || null;
  },

  onAuthStateChanged(callback) {
    const handler = () => callback();
    window.addEventListener(AUTH_EVENT, handler);
    return () => window.removeEventListener(AUTH_EVENT, handler);
  },

  async refreshAccessToken() {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return null;

    try {
      const baseUrl = import.meta.env.VITE_API_URL?.trim() || '';
      const url = baseUrl ? `${baseUrl}/api/v1/auth/refresh` : '/api/v1/auth/refresh';
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!response.ok) {
        this.clearTokens();
        return null;
      }

      const data = await response.json();
      localStorage.setItem(ACCESS_TOKEN_KEY, data.access_token);
      emitAuthChange();
      return data.access_token;
    } catch {
      this.clearTokens();
      return null;
    }
  },

  async getValidAccessToken() {
    let token = this.getAccessToken();
    if (!token) return null;

    if (isTokenExpired(token)) {
      token = await this.refreshAccessToken();
    }

    return token;
  },
};
