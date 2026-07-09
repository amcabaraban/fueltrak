const { User } = require('../models'); 
const jwt = require('jsonwebtoken'); 
 
class AuthService { 
  async register(userData) { 
    const exists = await User.findOne({ where: { email: userData.email } }); 
    if (exists) throw new Error('Email already registered'); 
    return await User.create(userData); 
  } 
 
  async login(email, password) { 
    const user = await User.findOne({ where: { email } }); 
    if (!user || !(await user.comparePassword(password))) throw new Error('Invalid credentials'); 
    if (!user.is_active) throw new Error('Account deactivated'); 
    await user.update({ last_login: new Date() }); 
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' }); 
    return { token, user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name } }; 
  } 
} 
module.exports = new AuthService(); 
