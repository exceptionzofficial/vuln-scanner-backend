// src/services/emailService.js
const nodemailer = require('nodemailer');

// In-memory OTP storage (for production, use Redis or DynamoDB)
const otpStore = new Map();

// OTP expiry time in milliseconds (10 minutes)
const OTP_EXPIRY = 10 * 60 * 1000;

// Transporter instance (created lazily)
let transporter = null;

/**
 * Get or create the email transporter (lazy initialization)
 */
function getTransporter() {
  if (!transporter) {
    console.log('📧 Creating email transporter...');
    console.log('EMAIL_USER:', process.env.EMAIL_USER ? '✅ Set' : '❌ Missing');
    console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Set' : '❌ Missing');

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error('Email credentials not configured. Check EMAIL_USER and EMAIL_PASS in .env');
    }

    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }
  return transporter;
}

/**
 * Generate a 6-digit OTP
 */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * Store OTP with expiry
 */
function storeOTP(email, otp) {
  const normalizedEmail = email.toLowerCase();
  otpStore.set(normalizedEmail, {
    otp,
    expiresAt: Date.now() + OTP_EXPIRY,
    attempts: 0,
  });

  // Auto-delete after expiry
  setTimeout(() => {
    otpStore.delete(normalizedEmail);
  }, OTP_EXPIRY);

  return otp;
}

/**
 * Verify OTP
 */
function verifyOTP(email, otp) {
  const normalizedEmail = email.toLowerCase();
  const stored = otpStore.get(normalizedEmail);

  if (!stored) {
    return { valid: false, error: 'OTP expired or not found. Please request a new one.' };
  }

  if (Date.now() > stored.expiresAt) {
    otpStore.delete(normalizedEmail);
    return { valid: false, error: 'OTP has expired. Please request a new one.' };
  }

  stored.attempts += 1;

  if (stored.attempts > 5) {
    otpStore.delete(normalizedEmail);
    return { valid: false, error: 'Too many failed attempts. Please request a new OTP.' };
  }

  if (stored.otp !== otp) {
    return { valid: false, error: 'Invalid OTP. Please try again.' };
  }

  // OTP is valid - delete it (one-time use)
  otpStore.delete(normalizedEmail);
  return { valid: true };
}

/**
 * Delete OTP (called after successful password reset)
 */
function deleteOTP(email) {
  const normalizedEmail = email.toLowerCase();
  otpStore.delete(normalizedEmail);
}

/**
 * Send OTP email with cyberpunk styling
 */
async function sendOTPEmail(email, otp) {
  const mailOptions = {
    from: {
      name: 'Cyber Scanner',
      address: process.env.EMAIL_USER,
    },
    to: email,
    subject: '🔐 Password Reset OTP - Cyber Scanner',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="margin: 0; padding: 0; background-color: #0a0a0a; font-family: 'Courier New', monospace;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0a0a0a; padding: 40px 20px;">
          <tr>
            <td align="center">
              <table width="100%" max-width="600" cellpadding="0" cellspacing="0" style="background-color: #111111; border: 2px solid #00ff41; border-radius: 12px; overflow: hidden;">
                
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%); padding: 30px; text-align: center; border-bottom: 1px solid #00ff41;">
                    <h1 style="margin: 0; color: #00ff41; font-size: 28px; letter-spacing: 4px; text-shadow: 0 0 10px #00ff41;">
                      🛡️ CYBER SCANNER
                    </h1>
                    <p style="margin: 10px 0 0; color: #666; font-size: 12px; letter-spacing: 2px;">
                      SECURITY AUTHENTICATION SYSTEM
                    </p>
                  </td>
                </tr>
                
                <!-- Content -->
                <tr>
                  <td style="padding: 40px 30px;">
                    <p style="color: #00ff41; font-size: 14px; margin: 0 0 20px;">
                      &gt; PASSWORD RESET REQUEST DETECTED
                    </p>
                    
                    <p style="color: #cccccc; font-size: 14px; line-height: 1.6; margin: 0 0 30px;">
                      We received a request to reset your password. Use the following One-Time Password (OTP) to proceed with the reset:
                    </p>
                    
                    <!-- OTP Box -->
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td align="center" style="padding: 20px;">
                          <div style="background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%); border: 2px solid #00ff41; border-radius: 8px; padding: 25px 40px; display: inline-block;">
                            <p style="margin: 0 0 10px; color: #666; font-size: 12px; letter-spacing: 2px;">
                              YOUR OTP CODE
                            </p>
                            <p style="margin: 0; color: #00ff41; font-size: 36px; font-weight: bold; letter-spacing: 12px; text-shadow: 0 0 20px #00ff41;">
                              ${otp}
                            </p>
                          </div>
                        </td>
                      </tr>
                    </table>
                    
                    <!-- Warning -->
                    <div style="background-color: rgba(255, 107, 53, 0.1); border: 1px solid #ff6b35; border-radius: 8px; padding: 15px; margin: 30px 0;">
                      <p style="margin: 0; color: #ff6b35; font-size: 12px;">
                        ⚠️ This OTP expires in <strong>10 minutes</strong>. Do not share this code with anyone.
                      </p>
                    </div>
                    
                    <p style="color: #666; font-size: 12px; line-height: 1.6; margin: 0;">
                      If you didn't request this password reset, please ignore this email or contact support if you believe your account has been compromised.
                    </p>
                  </td>
                </tr>
                
                <!-- Footer -->
                <tr>
                  <td style="background-color: #0a0a0a; padding: 20px 30px; text-align: center; border-top: 1px solid #333;">
                    <p style="margin: 0; color: #444; font-size: 10px; letter-spacing: 1px;">
                      CYBER SCANNER © ${new Date().getFullYear()} | SECURE CONNECTION ESTABLISHED
                    </p>
                    <p style="margin: 10px 0 0; color: #333; font-size: 10px;">
                      This is an automated message. Please do not reply.
                    </p>
                  </td>
                </tr>
                
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
    text: `
CYBER SCANNER - PASSWORD RESET

Your OTP Code: ${otp}

This code expires in 10 minutes.

If you didn't request this, please ignore this email.
    `,
  };

  try {
    const emailTransporter = getTransporter();
    const info = await emailTransporter.sendMail(mailOptions);
    console.log('✅ OTP email sent:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Email send error:', error.message);
    console.error('Full error:', error);
    throw error;
  }
}

module.exports = {
  generateOTP,
  storeOTP,
  verifyOTP,
  deleteOTP,
  sendOTPEmail,
};
