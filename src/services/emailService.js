const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  async sendOTP(email, otp) {
    const mailOptions = {
      from: '"FuelTrak" <noreply@fueltrak.com>',
      to: email,
      subject: 'FuelTrak - Email Verification OTP',
      html: `
        <div style="font-family: Arial, sans-serif; max-inline-size: 600px; margin: 0 auto;">
          <div style="background: #1e3a5f; padding: 20px; text-align: center;">
            <h1 style="color: #ffc857; margin: 0;">FuelTrak Logistics</h1>
          </div>
          <div style="padding: 30px; background: #fff;">
            <h2>Email Verification</h2>
            <p>Your OTP for email verification is:</p>
            <div style="background: #f0f4ff; padding: 20px; text-align: center; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; color: #1e3a5f; letter-spacing: 5px;">${otp}</span>
            </div>
            <p style="color: #666;">This OTP will expire in 10 minutes.</p>
            <p style="color: #666;">If you didn't request this, please ignore this email.</p>
          </div>
        </div>
      `
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendWelcomeEmail(email, companyName) {
    const mailOptions = {
      from: '"FuelTrak" <noreply@fueltrak.com>',
      to: email,
      subject: 'Welcome to FuelTrak Logistics',
      html: `
        <div style="font-family: Arial, sans-serif; max-inline-size: 600px; margin: 0 auto;">
          <div style="background: #1e3a5f; padding: 20px; text-align: center;">
            <h1 style="color: #ffc857; margin: 0;">Welcome to FuelTrak!</h1>
          </div>
          <div style="padding: 30px; background: #fff;">
            <h2>Account Activated</h2>
            <p>Dear ${companyName || 'Valued Client'},</p>
            <p>Your account has been successfully verified and activated.</p>
            <p>You can now:</p>
            <ul>
              <li>Submit Authority to Load (ATL)</li>
              <li>Track your truck dispatches</li>
              <li>Manage your truck fleet</li>
            </ul>
            <a href="${process.env.FRONTEND_URL}/login" style="display: inline-block; background: #1e3a5f; color: #fff; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-block-start: 20px;">Login to FuelTrak</a>
          </div>
        </div>
      `
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendATLNotification(email, atlDetails) {
    const mailOptions = {
      from: '"FuelTrak" <noreply@fueltrak.com>',
      to: email,
      subject: `ATL ${atlDetails.status} - ${atlDetails.plate_no}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-inline-size: 600px; margin: 0 auto;">
          <div style="background: #1e3a5f; padding: 20px; text-align: center;">
            <h1 style="color: #ffc857; margin: 0;">ATL Update</h1>
          </div>
          <div style="padding: 30px; background: #fff;">
            <h2>ATL ${atlDetails.status.toUpperCase()}</h2>
            <table style="inline-size: 100%; border-collapse: collapse;">
              <tr><td style="padding: 8px; border-block-end: 1px solid #eee;">SO Number</td><td style="padding: 8px; border-block-end: 1px solid #eee;">${atlDetails.so_number}</td></tr>
              <tr><td style="padding: 8px; border-block-end: 1px solid #eee;">Plate No</td><td style="padding: 8px; border-block-end: 1px solid #eee;">${atlDetails.plate_no}</td></tr>
              <tr><td style="padding: 8px; border-block-end: 1px solid #eee;">Driver</td><td style="padding: 8px; border-block-end: 1px solid #eee;">${atlDetails.driver_name}</td></tr>
              <tr><td style="padding: 8px; border-block-end: 1px solid #eee;">Status</td><td style="padding: 8px; border-block-end: 1px solid #eee; font-weight: bold;">${atlDetails.status}</td></tr>
            </table>
            <a href="${process.env.FRONTEND_URL}/atl" style="display: inline-block; background: #1e3a5f; color: #fff; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-block-start: 20px;">View ATL</a>
          </div>
        </div>
      `
    };

    await this.transporter.sendMail(mailOptions);
  }
}

module.exports = new EmailService();