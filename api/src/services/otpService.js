const NodeCache = require('node-cache');

class OTPService {
  constructor() {
    this.otpCache = new NodeCache({ stdTTL: 600 }); // 10 minutes
  }

  generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  storeOTP(email, otp) {
    this.otpCache.set(email, otp);
  }

  verifyOTP(email, otp) {
    const storedOTP = this.otpCache.get(email);
    if (storedOTP && storedOTP === otp) {
      this.otpCache.del(email);
      return true;
    }
    return false;
  }

  hasActiveOTP(email) {
    return this.otpCache.has(email);
  }
}

module.exports = new OTPService();