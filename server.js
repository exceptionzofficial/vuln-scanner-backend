// server.js - WITH DYNAMODB
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const subscriptionService = require('./src/services/subscriptionService');
require('dotenv').config();

// ✅ ADD THIS DEBUG INFO
console.log('🔧 Environment Check:');
console.log('AWS Region:', process.env.AWS_REGION);
console.log('AWS Access Key:', process.env.AWS_ACCESS_KEY_ID ? '✅ Set' : '❌ Missing');
console.log('AWS Secret Key:', process.env.AWS_SECRET_ACCESS_KEY ? '✅ Set' : '❌ Missing');
console.log('JWT Secret:', process.env.JWT_SECRET ? '✅ Set' : '❌ Missing');

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

// ==================== SUBSCRIPTION EXPIRY CHECK ====================

/**
 * Check if subscription expired and downgrade to FREE
 */
async function checkSubscriptionExpiry(user) {
  if (!user.subscriptionExpiryDate || user.subscriptionPlan === 'FREE') {
    return user;
  }
  
  const now = new Date();
  const expiry = new Date(user.subscriptionExpiryDate);
  
  // If subscription expired, downgrade to FREE
  if (now > expiry && user.isSubscriptionActive) {
    console.log('⚠️ Subscription expired for user:', user.userId);
    console.log('Expiry date:', user.subscriptionExpiryDate);
    console.log('Downgrading to FREE plan');
    
    const params = {
      TableName: 'vuln-scanner-users',
      Key: { userId: user.userId },
      UpdateExpression: `
        SET subscriptionPlan = :free,
            scanLimit = :limit,
            isSubscriptionActive = :inactive,
            subscriptionExpiredAt = :now,
            updatedAt = :now
      `,
      ExpressionAttributeValues: {
        ':free': 'FREE',
        ':limit': 3,
        ':inactive': false,
        ':now': now.toISOString(),
      },
      ReturnValues: 'ALL_NEW',
    };
    
    const { DynamoDBDocumentClient, UpdateCommand } = require('@aws-sdk/lib-dynamodb');
    const result = await dynamoService.dynamoDB.send(new UpdateCommand(params));
    return result.Attributes;
  }
  
  return user;
}

// Get usage (WITH EXPIRY CHECK)
app.get('/api/user/usage', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    // Get user
    let user = await dynamoService.getUserByEmail(decoded.email);
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Check if subscription expired
    user = await checkSubscriptionExpiry(user);
    
    // Check if scans need to be reset (monthly renewal)
    user = await dynamoService.checkAndResetScans(decoded.userId);

    const scansRemaining = Math.max(0, (user.scanLimit || 3) - (user.scansUsed || 0));
    const subscriptionActive = user.isSubscriptionActive !== false;
    
    let daysUntilExpiry = null;
    if (user.subscriptionExpiryDate && subscriptionActive) {
      daysUntilExpiry = Math.ceil(
        (new Date(user.subscriptionExpiryDate) - new Date()) / (1000 * 60 * 60 * 24)
      );
    }

    return res.json({
      success: true,
      usage: {
        scansUsed: user.scansUsed || 0,
        scanLimit: user.scanLimit || 3,
        scansRemaining,
        lastScanDate: user.lastScanDate,
        subscriptionPlan: user.subscriptionPlan || 'FREE',
        subscriptionActive,
        subscriptionExpiryDate: user.subscriptionExpiryDate,
        daysUntilExpiry: Math.max(0, daysUntilExpiry || 0),
        nextResetDate: user.nextResetDate,
      },
    });

  } catch (error) {
    console.error('Get usage error:', error);
    return res.status(500).json({ success: false, error: 'Failed to get usage' });
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

// Authenticated scan (WITH AUTO RESET CHECK)
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

    // Check if scans need to be reset (monthly renewal)
    let user = await dynamoService.checkAndResetScans(decoded.userId);
    
    if (!user) {
      user = await dynamoService.getUserByEmail(decoded.email);
    }
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Check scan limit
    const currentScansUsed = user.scansUsed || 0;
    const scanLimit = user.scanLimit || 3;
    const subscriptionPlan = user.subscriptionPlan || 'FREE';
    
    if (currentScansUsed >= scanLimit) {
      let upgradeMessage = '';
      
      if (subscriptionPlan === 'FREE') {
        upgradeMessage = 'Upgrade to PRO (50 scans/month) or ENTERPRISE (unlimited) to continue scanning!';
      } else if (subscriptionPlan === 'PRO') {
        upgradeMessage = 'Your PRO plan includes 50 scans per month. Upgrade to ENTERPRISE for unlimited scanning!';
      }
      
      const daysUntilReset = user.nextResetDate ? 
        Math.ceil((new Date(user.nextResetDate) - new Date()) / (1000 * 60 * 60 * 24)) : 
        30;
      
      return res.status(429).json({
        success: false,
        error: `Scan limit reached (${currentScansUsed}/${scanLimit})`,
        message: upgradeMessage,
        scansRemaining: 0,
        daysUntilReset: Math.max(0, daysUntilReset),
        currentPlan: subscriptionPlan,
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
    await dynamoService.updateUserScans(user.userId, currentScansUsed + 1);

    return res.json({
      success: true,
      scanId,
      scan: scanResult,
      scansRemaining: Math.max(0, scanLimit - (currentScansUsed + 1)),
      currentPlan: subscriptionPlan,
    });

  } catch (error) {
    console.error('Scan error:', error.message);
    return res.status(500).json({ 
      success: false,
      error: error.response?.data?.error || 'Scan failed' 
    });
  }
});


// Get user's scan history
app.get('/api/scans', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    console.log('Fetching scan history for user:', decoded.userId);

    // Get user's scans from DynamoDB
    const scans = await dynamoService.getUserScans(decoded.userId, 20);

    return res.json({
      success: true,
      scans,
      total: scans.length,
    });

  } catch (error) {
    console.error('Get scans error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to fetch scan history',
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


// ==================== SIMPLIFIED SUBSCRIPTION UPDATE ====================

/**
 * Update user subscription after RevenueCat confirms payment
 * POST /api/user/update-subscription
 * Body: { plan: 'PRO', scanLimit: 50 }
 */
app.post('/api/user/update-subscription', async (req, res) => {
  try {
    const { plan, scanLimit } = req.body;
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    console.log('📥 Updating subscription for user:', decoded.userId);
    console.log('Plan:', plan, '| Scan Limit:', scanLimit);

    // Validate plan
    const validPlans = ['FREE', 'PRO', 'ENTERPRISE'];
    if (!validPlans.includes(plan)) {
      return res.status(400).json({ success: false, error: 'Invalid plan' });
    }

    // Update user's scan limit in DynamoDB
    const updatedUser = await dynamoService.updateUserScanLimit(decoded.userId, {
      plan,
      scanLimit,
    });

    console.log('✅ Subscription updated successfully');

    return res.json({
      success: true,
      message: 'Subscription updated successfully',
      user: {
        userId: updatedUser.userId,
        plan: updatedUser.subscriptionPlan || plan,
        scanLimit: updatedUser.scanLimit,
        scansUsed: updatedUser.scansUsed || 0,
        scansRemaining: (updatedUser.scanLimit || 0) - (updatedUser.scansUsed || 0),
      },
    });
  } catch (error) {
    console.error('❌ Update subscription error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to update subscription',
      details: error.message,
    });
  }
});


// ==================== ERROR HANDLING ====================
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Verify subscription purchase
app.post('/api/subscription/verify', async (req, res) => {
  try {
    const { productId, purchaseToken, platform } = req.body;
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    if (platform === 'android') {
      const packageName = 'com.vulnscannerapp'; // Your app package name
      
      // Verify with Google Play
      const verification = await subscriptionService.verifyAndroidSubscription(
        packageName,
        productId,
        purchaseToken
      );

      // Determine subscription plan
      let plan = 'FREE';
      let scanLimit = 3;

      if (productId === 'nova_scanner_pro_monthly') {
        plan = 'PRO';
        scanLimit = 50;
      } else if (productId === 'nova_scanner_enterprise_monthly') {
        plan = 'ENTERPRISE';
        scanLimit = 999999;
      }

      // Update user subscription
      await subscriptionService.updateUserSubscription(decoded.userId, {
        plan,
        scanLimit,
        expiry: new Date(verification.expiryTimeMillis).toISOString(),
      });

      return res.json({
        success: true,
        message: 'Subscription verified',
        plan,
        scanLimit,
      });
    }

    return res.status(400).json({ success: false, error: 'Invalid platform' });
  } catch (error) {
    console.error('Verify subscription error:', error);
    return res.status(500).json({ success: false, error: 'Verification failed' });
  }
});

// Add at the top with other requires


// ==================== SUBSCRIPTION ROUTES ====================

/**
 * Sync RevenueCat subscription to backend
 * POST /api/subscription/sync-revenuecat
 */
app.post('/api/subscription/sync-revenuecat', async (req, res) => {
  try {
    const { revenuecat_user_id, plan, scanLimit, active_subscriptions } = req.body;
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    console.log('📥 Syncing subscription for user:', decoded.userId);

    // Sync subscription data
    const result = await subscriptionService.syncSubscription(decoded.userId, {
      revenuecat_user_id,
      plan,
      scanLimit,
      active_subscriptions,
    });

    return res.json({
      success: true,
      message: 'Subscription synced successfully',
      plan,
      scanLimit,
      user: result.user,
    });
  } catch (error) {
    console.error('❌ Sync subscription error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to sync subscription',
      details: error.message,
    });
  }
});

/**
 * Get user's subscription status
 * GET /api/subscription/status
 */
app.get('/api/subscription/status', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    const status = await subscriptionService.getSubscriptionStatus(decoded.userId);

    return res.json({
      success: true,
      subscription: status,
    });
  } catch (error) {
    console.error('❌ Get subscription status error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to get subscription status',
    });
  }
});

/**
 * RevenueCat Webhook Handler (for production)
 * POST /api/subscription/webhook
 */
app.post('/api/subscription/webhook', async (req, res) => {
  try {
    const webhookData = req.body;
    
    console.log('🔔 Received RevenueCat webhook');

    // Verify webhook signature (optional but recommended)
    // const signature = req.headers['x-revenuecat-signature'];
    // Verify signature here...

    await subscriptionService.handleWebhook(webhookData);

    return res.json({ success: true });
  } catch (error) {
    console.error('❌ Webhook error:', error);
    return res.status(500).json({
      success: false,
      error: 'Webhook processing failed',
    });
  }
});

/**
 * Cancel subscription
 * POST /api/subscription/cancel
 */
app.post('/api/subscription/cancel', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');

    const result = await subscriptionService.cancelSubscription(decoded.userId);

    return res.json({
      success: true,
      message: 'Subscription canceled successfully',
      user: result.user,
    });
  } catch (error) {
    console.error('❌ Cancel subscription error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to cancel subscription',
    });
  }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🐍 Python Scanner: ${PYTHON_SCANNER_URL}`);
  console.log('💾 Storage: DynamoDB');
});

module.exports = app;
