// api/subscription/status.js
const jwt = require('jsonwebtoken');
const subscriptionService = require('../../src/services/subscriptionService');

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const status = await subscriptionService.getSubscriptionStatus(decoded.userId);

    return res.status(200).json({
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
};
