// src/middleware/rateLimiter.js
const dynamoService = require('../services/dynamoService');

const rateLimiter = async (req, res, next) => {
  try {
    const userId = req.userId;

    // Get user data
    const user = await dynamoService.getUserById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
      });
    }

    // Check scan limit
    if (user.scansUsed >= user.scanLimit) {
      return res.status(429).json({
        success: false,
        error: `Scan limit reached. You have used ${user.scansUsed}/${user.scanLimit} scans this month.`,
        scansUsed: user.scansUsed,
        scanLimit: user.scanLimit,
      });
    }

    // Attach user to request
    req.user = user;
    next();

  } catch (error) {
    console.error('Rate limiter error:', error);
    return res.status(500).json({
      success: false,
      error: 'Rate limiting check failed',
    });
  }
};

module.exports = rateLimiter;
