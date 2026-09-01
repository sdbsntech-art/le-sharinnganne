const AUTH_KEY = 'sharinnganne_auth';
const API_BASE = window.location.origin;

function getStoredAuth() {
  try {
    const stored = localStorage.getItem(AUTH_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch { return null; }
}

function saveAuth(token, email, uniqueKey, isAdmin) {
  localStorage.setItem(AUTH_KEY, JSON.stringify({ token, email, unique_key: uniqueKey, is_admin: isAdmin }));
}

function clearAuth() {
  localStorage.removeItem(AUTH_KEY);
}

function isAuthenticated() {
  const auth = getStoredAuth();
  return auth && auth.token;
}

function isAdmin() {
  const auth = getStoredAuth();
  return auth && auth.is_admin;
}

function getToken() {
  const auth = getStoredAuth();
  return auth ? auth.token : null;
}

function getUserEmail() {
  const auth = getStoredAuth();
  return auth ? auth.email : null;
}

function getUserKey() {
  const auth = getStoredAuth();
  return auth ? auth.unique_key : null;
}

async function apiCall(endpoint, options = {}) {
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };
  if (token) {
    headers['Authorization'] = 'Bearer ' + token;
  }
  const response = await fetch(API_BASE + endpoint, { ...options, headers });
  const data = await response.json();
  if (!response.ok) {
    throw { status: response.status, error: data.error || 'Erreur API' };
  }
  return data;
}

async function loginUser(email, password) {
  const data = await apiCall('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  saveAuth(data.token, data.email, data.unique_key, data.is_admin);
  return data;
}

async function registerUser(email, password) {
  const data = await apiCall('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password, accept_terms: true }),
  });
  return data;
}

function logoutUser() {
  clearAuth();
  window.location.reload();
}
