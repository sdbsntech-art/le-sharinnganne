const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * Vérifie le token JWT et retourne le payload de l'utilisateur.
 * Si invalide, lève une erreur avec un code statut.
 */
const checkAuth = (event) => {
  const JWT_SECRET = process.env.JWT_SECRET;
  const authHeader = event.headers.authorization || event.headers.Authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw { statusCode: 401, message: 'Non authentifié' };
  }

  const token = authHeader.split(' ')[1];
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (e) {
    throw { statusCode: 401, message: 'Session invalide ou expirée' };
  }
};

const checkAdmin = (event) => {
  const user = checkAuth(event);
  if (!user.is_admin) {
    throw { statusCode: 403, message: 'Accès admin requis' };
  }
  return user;
};

const genUniqueKey = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'SHR-' + Array.from({ length: 6 }, () =>
    chars[crypto.randomInt(chars.length)]
  ).join('');
};

const generateToken = (user) => {
  const JWT_SECRET = process.env.JWT_SECRET;
  return jwt.sign(
    { email: user.email, is_admin: user.is_admin, uid: user.id },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '24h' }
  );
};

module.exports = { checkAuth, checkAdmin, genUniqueKey, generateToken };