const authService = require('../services/authService'); 
 
class AuthController { 
  async register(req, res) { 
    try { const user = await authService.register(req.body); res.status(201).json({ status: 'success', user }); } 
    catch (error) { res.status(400).json({ status: 'error', message: error.message }); } 
  } 
  async login(req, res) { 
    try { const result = await authService.login(req.body.email, req.body.password); res.json({ status: 'success', ...result }); } 
    catch (error) { res.status(401).json({ status: 'error', message: error.message }); } 
  } 
} 
module.exports = new AuthController(); 
