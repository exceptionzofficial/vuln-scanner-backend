// api/subscription/sync-revenuecat.js
const jwt = require('jsonwebtoken');
const subscriptionService = require('../../src/services/subscriptionService');

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  // Handle OPTIONS request
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

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

    return res.status(200).json({
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
};
