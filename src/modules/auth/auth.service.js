const { User } = require('../../models');
const jwt = require('jsonwebtoken');

class AuthService {
  async findUserByEmail(email) {
    return await User.findOne({ where: { email } });
  }

  async createUser(userData) {
    return await User.create(userData);
  }

  async login(email, password) {
    const user = await User.findOne({ where: { email } });
    
    if (!user) throw new Error('Invalid credentials');
    if (!user.is_verified) throw new Error('Please verify your email first');
    if (!user.is_active) throw new Error('Account deactivated');
    
    const isMatch = await user.comparePassword(password);
    if (!isMatch) throw new Error('Invalid credentials');

    await user.update({ last_login: new Date() });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );

    return {
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        mobile: user.mobile,
        company_name: user.company_name,
        is_verified: user.is_verified
      }
    };
  }
}

module.exports = new AuthService();