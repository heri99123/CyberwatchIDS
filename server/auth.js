// CyberWatch IDS — Auth Module
// JWT-based authentication with multi-tenant organization support
const crypto = require('crypto');

// In production, use environment variable; fallback to a development secret
const JWT_SECRET = process.env.JWT_SECRET || 'cyberwatch-ids-secret-key-2024-change-in-prod';
const JWT_EXPIRY = 7 * 24 * 60 * 60; // 7 days in seconds

// Simple password hashing using Node.js built-in crypto (PBKDF2)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const iterations = 10000;
  const keyLength = 64;
  const hash = crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512').toString('hex');
  return `${iterations}:${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const parts = storedHash.split(':');
  if (parts.length !== 3) return false;
  const iterations = parseInt(parts[0]);
  const salt = parts[1];
  const hash = parts[2];
  const testHash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(testHash, 'hex'));
}

// Simple JWT implementation (no external dependency needed)
function base64UrlEncode(obj) {
  const json = typeof obj === 'string' ? obj : JSON.stringify(obj);
  return Buffer.from(json).toString('base64url');
}

function base64UrlDecode(str) {
  return Buffer.from(str, 'base64url').toString('utf8');
}

function signJWT(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + JWT_EXPIRY });
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  return `${data}.${signature}`;
}

function verifyJWT(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(`${encodedHeader}.${encodedPayload}`).digest('base64url');
  
  if (signature !== expectedSig) return null;
  
  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// Generate a random API key
function generateApiKey() {
  return 'cw_' + crypto.randomBytes(24).toString('hex');
}

// Middleware: require authentication
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  let token = null;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (req.headers['x-api-key']) {
    // API key authentication
    const apiKey = req.headers['x-api-key'];
    req.apiKey = apiKey;
    // API key auth will be handled by the route handler
    return next();
  }
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }
  
  const payload = verifyJWT(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token', code: 'INVALID_TOKEN' });
  }
  
  req.user = {
    id: payload.sub,
    email: payload.email,
    name: payload.name,
    role: payload.role,
    orgId: payload.orgId,
    orgName: payload.orgName
  };
  
  next();
}

// Middleware: require admin role
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required', code: 'FORBIDDEN' });
  }
  next();
}

module.exports = {
  hashPassword,
  verifyPassword,
  signJWT,
  verifyJWT,
  generateApiKey,
  requireAuth,
  requireAdmin,
  JWT_SECRET
};
