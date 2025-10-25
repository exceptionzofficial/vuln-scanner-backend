// server.js
const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const authController = require('./src/controllers/authController');
const userController = require('./src/controllers/userController');
const { authenticate } = require('./src/middleware/authenticate');
const rateLimiter = require('./src/middleware/rateLimiter');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Python Scanner Service URL
const PYTHON_SCANNER_URL = process.env.PYTHON_SCANNER_URL || 'https://vuln-scanner-python.vercel.app';

// Health check
app.get('/', (req, res) => {
  res.json({
    service: 'VulnScanner API (Node.js)',
    version: '1.0.0',
    status: 'running',
    pythonScanner: PYTHON_SCANNER_URL
  });
});

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.get('/api/auth/verify', authenticate, authController.verifyToken);

// ==================== USER ROUTES ====================
app.get('/api/user/profile', authenticate, userController.getProfile);
app.get('/api/user/usage', authenticate, userController.getUsage);

// ==================== SCAN ROUTES ====================

// Test scan (no auth)
app.post('/test-scan', async (req, res) => {
  try {
    const { targetUrl } = req.body;
    
    if (!targetUrl) {
      return res.status(400).json({ error: 'Target URL required' });
    }

    console.log('Forwarding scan request to Python service:', targetUrl);

    // Call Python service
    const response = await axios.post(
      `${PYTHON_SCANNER_URL}/api/scan`,
      { targetUrl },
      { 
        timeout: 120000,
        headers: { 'Content-Type': 'application/json' }
      }
    );

    return res.json(response.data);

  } catch (error) {
    console.error('Scan error:', error.message);
    return res.status(500).json({ 
      error: error.response?.data?.error || 'Scan failed' 
    });
  }
});

// Authenticated scan (with rate limiting)
app.post('/api/scans', authenticate, rateLimiter, async (req, res) => {
  try {
    const { targetUrl } = req.body;
    const userId = req.userId;
    
    console.log(`User ${userId} requesting scan for: ${targetUrl}`);

    // Call Python service
    const scanResponse = await axios.post(
      `${PYTHON_SCANNER_URL}/api/scan`,
      { targetUrl },
      { 
        timeout: 120000,
        headers: { 'Content-Type': 'application/json' }
      }
    );

    const scanResult = scanResponse.data;

    // TODO: Save scan to DynamoDB with userId
    // const savedScan = await saveScanToDatabase(userId, scanResult);

    // Update user scan count
    // await updateUserScanCount(userId);

    return res.json({
      success: true,
      scan: scanResult,
      scanId: Date.now().toString(), // TODO: Use actual scan ID from DB
      scansLeft: 2 // TODO: Get from user record
    });

  } catch (error) {
    console.error('Scan error:', error.message);
    return res.status(500).json({ 
      error: error.response?.data?.error || 'Scan failed' 
    });
  }
});

// ==================== ERROR HANDLING ====================
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`🚀 Node.js server: http://localhost:${PORT}`);
    console.log(`🐍 Python scanner: ${PYTHON_SCANNER_URL}`);
  });
}

module.exports = app;
