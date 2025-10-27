// src/controllers/userController.js
const dynamoService = require('../services/dynamoService');

class UserController {
  // Get user profile
  async getProfile(req, res) {
    try {
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
          createdAt: user.createdAt,
          lastScanDate: user.lastScanDate,
        },
      });

    } catch (error) {
      console.error('Get profile error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get profile',
      });
    }
  }

  // Get usage stats
  async getUsage(req, res) {
    try {
      const user = await dynamoService.getUserById(req.userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
        });
      }

      const scansRemaining = user.scanLimit - user.scansUsed;

      return res.status(200).json({
        success: true,
        usage: {
          scansUsed: user.scansUsed,
          scanLimit: user.scanLimit,
          scansRemaining: Math.max(0, scansRemaining),
          lastScanDate: user.lastScanDate,
        },
      });

    } catch (error) {
      console.error('Get usage error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get usage stats',
      });
    }
  }
}

module.exports = new UserController();
