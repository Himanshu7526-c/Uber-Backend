const userModel = require('../models/user.model');
const captainModel = require('../models/captain.model');
const jwt = require('jsonwebtoken');
const blackListTokenModel = require('../models/blackListToken.model');

// Reusable token extraction function
const getTokenFromRequest = (req) => {
  return req.cookies.token || req.headers.authorization?.split(' ')[1];
};

// Reusable blacklist check
const isTokenBlacklisted = async (token) => {
  return await blackListTokenModel.findOne({ token });
};

module.exports.authUser = async (req, res, next) => {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).json({ message: 'Unauthorized - No token' });

  if (await isTokenBlacklisted(token))
    return res.status(401).json({ message: 'Unauthorized - Blacklisted token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(decoded._id);
    if (!user) return res.status(401).json({ message: 'Unauthorized - User not found' });

    req.user = user;
    next();
  } catch (err) {
    console.error('User auth error:', err.message);
    res.status(401).json({ message: 'Unauthorized - Invalid token' });
  }
};

module.exports.authCaptain = async (req, res, next) => {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).json({ message: 'Unauthorized - No token' });

  if (await isTokenBlacklisted(token))
    return res.status(401).json({ message: 'Unauthorized - Blacklisted token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const captain = await captainModel.findById(decoded._id);
    if (!captain) return res.status(401).json({ message: 'Unauthorized - Captain not found' });

    req.captain = captain;
    next();
  } catch (err) {
    console.error('Captain auth error:', err.message);
    res.status(401).json({ message: 'Unauthorized - Invalid token' });
  }
};
