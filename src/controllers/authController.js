// src/controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const dynamoService = require('../services/dynamoService');

class AuthController {
  // ==================== REGISTER ====================
  async register(req, res) {
    try {
      const { name, email, password } = req.body;

      // Validation
      if (!name || !email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Name, email, and password are required',
        });
      }

      // Email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid email format',
        });
      }

      // Password validation
      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          error: 'Password must be at least 6 characters',
        });
      }

      // Check if user exists
      const existingUser = await dynamoService.getUserByEmail(email);
      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: 'Email already registered',
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user
      const userId = uuidv4();
      const user = await dynamoService.createUser({
        userId,
        name,
        email,
        password: hashedPassword,
      });

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.userId, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );

      // Return success
      return res.status(201).json({
        success: true,
        message: 'Registration successful',
        token,
        user: {
          userId: user.userId,
          name: user.name,
          email: user.email,
          scansUsed: user.scansUsed,
          scanLimit: user.scanLimit,
        },
      });

    } catch (error) {
      console.error('Register error:', error);
      return res.status(500).json({
        success: false,
        error: 'Registration failed. Please try again.',
      });
    }
  }

  // ==================== LOGIN ====================
  async login(req, res) {
    try {
      const { email, password } = req.body;

      // Validation
      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Email and password are required',
        });
      }

      // Get user by email
      const user = await dynamoService.getUserByEmail(email);
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Invalid email or password',
        });
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          error: 'Invalid email or password',
        });
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.userId, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );

      // Return success
      return res.status(200).json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          userId: user.userId,
          name: user.name,
          email: user.email,
          scansUsed: user.scansUsed,
          scanLimit: user.scanLimit,
        },
      });

    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({
        success: false,
        error: 'Login failed. Please try again.',
      });
    }
  }

  // ==================== VERIFY TOKEN ====================
  async verifyToken(req, res) {
    try {
      // User already attached by authenticate middleware
      const user = await dynamoService.getUserById(req.userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
        });
      }

      return res.status(200).json({
        success: true,
        user: {
          userId: user.userId,
          name: user.name,
          email: user.email,
          scansUsed: user.scansUsed,
          scanLimit: user.scanLimit,
        },
      });

    } catch (error) {
      console.error('Verify token error:', error);
      return res.status(500).json({
        success: false,
        error: 'Token verification failed',
      });
    }
  }
}

module.exports = new AuthController();
