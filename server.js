// server.js - WITH DYNAMODB
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const dynamoService = require('./src/services/dynamoService');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Python Scanner URL
const PYTHON_SCANNER_URL = process.env.PYTHON_SCANNER_URL || 'https://vuln-scanner-python.vercel.app';

// ==================== HEALTH CHECK ====================
app.get('/', (req, res) => {
  res.json({
    service: 'VulnScanner API',
    version: '1.0.0',
    status: 'running',
    storage: 'DynamoDB',
    pythonScanner: PYTHON_SCANNER_URL,
  });
});

// ==================== AUTH ROUTES ====================

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    console.log('Register attempt:', { name, email });

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
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      scansUsed: 0,
      scanLimit: 3,
      lastScanDate: null,
    });

    console.log('User registered:', email);

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.userId, email: user.email },
      process.env.JWT_SECRET || 'default-secret-key',
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
      error: 'Registration failed: ' + error.message,
    });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('Login attempt:', email);

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required',
      });
    }

    // Get user
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

    console.log('User logged in:', email);

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.userId, email: user.email },
      process.env.JWT_SECRET || 'default-secret-key',
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
      error: 'Login failed: ' + error.message,
    });
  }
});

// VERIFY TOKEN
app.get('/api/auth/verify', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'No token provided',
      });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    const user = await dynamoService.getUserByEmail(decoded.email);
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
    return res.status(401).json({
      success: false,
      error: 'Invalid token',
    });
  }
});

// ==================== USER ROUTES ====================

// Get usage
app.get('/api/user/usage', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    const user = await dynamoService.getUserByEmail(decoded.email);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    return res.json({
      success: true,
      usage: {
        scansUsed: user.scansUsed,
        scanLimit: user.scanLimit,
        scansRemaining: Math.max(0, user.scanLimit - user.scansUsed),
        lastScanDate: user.lastScanDate,
      },
    });

  } catch (error) {
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
});

// ==================== SCAN ROUTES ====================

// Test scan (no auth)
app.post('/test-scan', async (req, res) => {
  try {
    const { targetUrl } = req.body;
    
    if (!targetUrl || !targetUrl.startsWith('http')) {
      return res.status(400).json({
        success: false,
        error: 'Valid URL required',
      });
    }

    console.log('Test scan:', targetUrl);

    const response = await axios.post(
      `${PYTHON_SCANNER_URL}/api/scan`,
      { targetUrl },
      { timeout: 120000 }
    );

    return res.json(response.data);

  } catch (error) {
    console.error('Test scan error:', error.message);
    return res.status(500).json({ 
      success: false,
      error: error.response?.data?.error || 'Scan failed' 
    });
  }
});

// Authenticated scan
app.post('/api/scans', async (req, res) => {
  try {
    const { targetUrl } = req.body;
    
    // Verify token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    const user = await dynamoService.getUserByEmail(decoded.email);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Check scan limit
    if (user.scansUsed >= user.scanLimit) {
      return res.status(429).json({
        success: false,
        error: `Scan limit reached (${user.scansUsed}/${user.scanLimit})`,
      });
    }

    console.log('Authenticated scan:', targetUrl);

    // Call Python scanner
    const scanResponse = await axios.post(
      `${PYTHON_SCANNER_URL}/api/scan`,
      { targetUrl },
      { timeout: 120000 }
    );

    const scanResult = scanResponse.data;

    // Save scan to DynamoDB
    const scanId = uuidv4();
    await dynamoService.createScan({
      scanId,
      userId: user.userId,
      targetUrl: scanResult.targetUrl,
      scanTime: scanResult.scanTime,
      vulnerabilitiesFound: scanResult.vulnerabilitiesFound,
      riskLevel: scanResult.summary.riskLevel,
      riskScore: scanResult.summary.riskScore,
      vulnerabilities: scanResult.vulnerabilities,
      summary: scanResult.summary,
    });

    // Update user scan count
    await dynamoService.updateUserScans(user.userId, user.scansUsed + 1);

    return res.json({
      success: true,
      scanId,
      scan: scanResult,
      scansRemaining: Math.max(0, user.scanLimit - (user.scansUsed + 1)),
    });

  } catch (error) {
    console.error('Scan error:', error.message);
    return res.status(500).json({ 
      success: false,
      error: error.response?.data?.error || 'Scan failed' 
    });
  }
});

// Get scan history
app.get('/api/scans', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    const scans = await dynamoService.getUserScans(decoded.userId, 10);

    return res.json({
      success: true,
      scans,
      total: scans.length,
    });

  } catch (error) {
    console.error('Get scans error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to get scan history',
    });
  }
});

// Get specific scan
app.get('/api/scans/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    const scan = await dynamoService.getScanById(scanId, decoded.userId);

    if (!scan) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found',
      });
    }

    return res.json({
      success: true,
      scan,
    });

  } catch (error) {
    console.error('Get scan error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to get scan',
    });
  }
});

// ==================== ERROR HANDLING ====================
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🐍 Python Scanner: ${PYTHON_SCANNER_URL}`);
  console.log('💾 Storage: DynamoDB');
});

module.exports = app;
