const authService = require('./auth.service');
const otpService = require('../../services/otpService');
const emailService = require('../../services/emailService');

class AuthController {
  async register(req, res) {
    try {
      const { email, password, mobile, company_name } = req.body;

      // Validate mobile format
      const mobileRegex = /^(09\d{9}|\+639\d{9})$/;
      if (!mobileRegex.test(mobile)) {
        return res.status(400).json({ error: 'Invalid mobile format. Use 09XXXXXXXXX or +639XXXXXXXXX' });
      }

      // Check if email exists
      const existingUser = await authService.findUserByEmail(email);
      if (existingUser) {
        if (existingUser.is_verified) {
          return res.status(400).json({ error: 'Email already registered' });
        }
        // Resend OTP for unverified user
        const otp = otpService.generateOTP();
        otpService.storeOTP(email, otp);
        await existingUser.update({ verification_otp: otp, otp_expiry: new Date(Date.now() + 600000) });
        await emailService.sendOTP(email, otp);
        return res.json({ message: 'OTP resent to your email', email });
      }

      // Create user
      const user = await authService.createUser({ email, password, mobile, company_name });
      
      // Generate and send OTP
      const otp = otpService.generateOTP();
      otpService.storeOTP(email, otp);
      await user.update({ verification_otp: otp, otp_expiry: new Date(Date.now() + 600000) });
      await emailService.sendOTP(email, otp);

      res.status(201).json({
        status: 'success',
        message: 'Registration successful. Please verify your email with the OTP sent.',
        email
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async verifyOTP(req, res) {
    try {
      const { email, otp } = req.body;
      const user = await authService.findUserByEmail(email);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      if (user.is_verified) {
        return res.json({ message: 'Email already verified' });
      }

      const isValid = otpService.verifyOTP(email, otp);
      if (!isValid) {
        return res.status(400).json({ error: 'Invalid or expired OTP' });
      }

      await user.update({ is_verified: true, verification_otp: null, otp_expiry: null });
      await emailService.sendWelcomeEmail(email, user.company_name);

      res.json({ status: 'success', message: 'Email verified successfully. You can now login.' });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async resendOTP(req, res) {
    try {
      const { email } = req.body;
      const user = await authService.findUserByEmail(email);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      if (user.is_verified) {
        return res.json({ message: 'Email already verified' });
      }

      const otp = otpService.generateOTP();
      otpService.storeOTP(email, otp);
      await user.update({ verification_otp: otp, otp_expiry: new Date(Date.now() + 600000) });
      await emailService.sendOTP(email, otp);

      res.json({ message: 'OTP resent to your email' });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;
      const result = await authService.login(email, password);
      res.json({ status: 'success', ...result });
    } catch (error) {
      res.status(401).json({ error: error.message });
    }
  }

  async getProfile(req, res) {
    res.json({ status: 'success', user: req.user });
  }

  async updateProfile(req, res) {
    try {
      const { mobile, company_name } = req.body;
      await req.user.update({ mobile, company_name });
      res.json({ status: 'success', message: 'Profile updated', user: req.user });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }
}

module.exports = new AuthController();