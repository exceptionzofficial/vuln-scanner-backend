// server.js
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const authController = require('./src/controllers/authController');
const scanController = require('./src/controllers/scanController');
const userController = require('./src/controllers/userController');
const { authenticate } = require('./src/middleware/authenticate');
const rateLimiter = require('./src/middleware/rateLimiter');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/', (req, res) => {
  res.json({
    service: 'VulnScanner API',
    version: '1.0.0',
    status: 'running',
    timestamp: new Date().toISOString()
  });
});

// ==================== TEST SCAN ROUTE (NO AUTH) ====================
// server.js - Update test-scan route
app.post('/test-scan', async (req, res) => {
  try {
    const { targetUrl } = req.body;
    
    if (!targetUrl || !targetUrl.startsWith('http')) {
      return res.status(400).json({
        success: false,
        error: 'Valid URL required (http:// or https://)'
      });
    }

    console.log(`Test scan requested for: ${targetUrl}`);

    // Check if running on Vercel
    const isVercel = process.env.VERCEL === '1';
    
    if (isVercel) {
      // On Vercel: Call Python API endpoint
      const axios = require('axios');
      const baseUrl = process.env.VERCEL_URL || 'vuln-scanner-backend-five.vercel.app';
      const pythonApiUrl = `https://${baseUrl}/api/scanner`;
      
      console.log('Calling Python API:', pythonApiUrl);
      
      const response = await axios.post(pythonApiUrl, { targetUrl }, {
        timeout: 60000,
        headers: { 'Content-Type': 'application/json' }
      });
      
      return res.status(200).json(response.data);
      
    } else {
      // Local: Use pythonService
      const PythonService = require('./src/services/pythonService');
      const scanResult = await PythonService.executeScan(targetUrl);
      return res.status(200).json(scanResult);
    }

  } catch (error) {
    console.error('Test scan error:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Scan failed'
    });
  }
});

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.get('/api/auth/verify', authenticate, authController.verifyToken);

// ==================== USER ROUTES ====================
app.get('/api/user/profile', authenticate, userController.getProfile);
app.get('/api/user/usage', authenticate, userController.getUsage);
app.put('/api/user/profile', authenticate, userController.updateProfile);

// ==================== SCAN ROUTES ====================
app.post('/api/scans', authenticate, rateLimiter, scanController.submitScan);
app.get('/api/scans/:scanId', authenticate, scanController.getScanResult);
app.get('/api/scans', authenticate, scanController.getScanHistory);
app.delete('/api/scans/:scanId', authenticate, scanController.deleteScan);

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

// Start server
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

module.exports = app;
