const jwt = require('jsonwebtoken'); 
const { User } = require('../models'); 
 
const authenticate = async (req, res, next) => { 
  try { 
    const token = req.header('Authorization')?.replace('Bearer ', ''); 
    if (!token) throw new Error(); 
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret'); 
    const user = await User.findByPk(decoded.id); 
    if (!user || !user.is_active) throw new Error(); 
    req.user = user; 
    next(); 
  } catch (error) { 
    res.status(401).json({ status: 'error', message: 'Please authenticate' }); 
  } 
}; 
 
const authorize = (...roles) => { 
  return (req, res, next) => { 
    if (!roles.includes(req.user.role)) return res.status(403).json({ status: 'error', message: 'Access denied' }); 
    next(); 
  }; 
}; 
module.exports = { authenticate, authorize }; 
