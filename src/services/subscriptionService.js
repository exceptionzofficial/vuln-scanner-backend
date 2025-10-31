// src/services/subscriptionService.js - RevenueCat Subscription Management
const { UpdateCommand, GetCommand } = require('@aws-sdk/lib-dynamodb');
const dynamoService = require('./dynamoService');

// Get dynamoDB client from dynamoService
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient } = require('@aws-sdk/lib-dynamodb');

const client = new DynamoDBClient({
  region: process.env.AWS_REGION || 'ap-south-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const dynamoDB = DynamoDBDocumentClient.from(client);

class SubscriptionService {
  /**
   * Sync RevenueCat subscription data to DynamoDB
   */
  async syncSubscription(userId, subscriptionData) {
    try {
      const { 
        revenuecat_user_id, 
        plan, 
        scanLimit, 
        active_subscriptions,
      } = subscriptionData;

      console.log('📥 Syncing subscription for user:', userId);
      console.log('Plan:', plan, '| Scan Limit:', scanLimit);

      // Update user's subscription info in DynamoDB
      const params = {
        TableName: 'vuln-scanner-users',
        Key: { userId },
        UpdateExpression: `
          SET subscriptionPlan = :plan,
              scanLimit = :limit,
              revenuecatUserId = :rcUserId,
              activeSubscriptions = :subs,
              subscriptionSyncedAt = :now,
              updatedAt = :now
        `,
        ExpressionAttributeValues: {
          ':plan': plan,
          ':limit': scanLimit,
          ':rcUserId': revenuecat_user_id || userId,
          ':subs': active_subscriptions || [],
          ':now': new Date().toISOString(),
        },
        ReturnValues: 'ALL_NEW',
      };

      const result = await dynamoDB.send(new UpdateCommand(params));

      console.log('✅ Subscription synced successfully');
      return {
        success: true,
        user: result.Attributes,
      };
    } catch (error) {
      console.error('❌ Sync subscription error:', error);
      throw error;
    }
  }

  /**
   * Get user's subscription status
   */
  async getSubscriptionStatus(userId) {
    try {
      const params = {
        TableName: 'vuln-scanner-users',
        Key: { userId },
      };

      const result = await dynamoDB.send(new GetCommand(params));
      const user = result.Item;

      if (!user) {
        return {
          plan: 'FREE',
          scanLimit: 3,
          scansUsed: 0,
          scansRemaining: 3,
        };
      }

      return {
        plan: user.subscriptionPlan || 'FREE',
        scanLimit: user.scanLimit || 3,
        scansUsed: user.scansUsed || 0,
        scansRemaining: (user.scanLimit || 3) - (user.scansUsed || 0),
        revenuecatUserId: user.revenuecatUserId,
        activeSubscriptions: user.activeSubscriptions || [],
        subscriptionSyncedAt: user.subscriptionSyncedAt,
      };
    } catch (error) {
      console.error('❌ Get subscription status error:', error);
      throw error;
    }
  }

  /**
   * Handle RevenueCat webhook events (for production)
   */
  async handleWebhook(webhookData) {
    try {
      const { event, app_user_id, product_id, entitlements } = webhookData;

      console.log('🔔 RevenueCat Webhook:', event);
      console.log('User:', app_user_id);
      console.log('Product:', product_id);

      // Determine plan from entitlements
      let plan = 'FREE';
      let scanLimit = 3;

      if (entitlements && entitlements.pro && entitlements.pro.expires_date) {
        plan = 'PRO';
        scanLimit = 50;
      }

      if (entitlements && entitlements.enterprise && entitlements.enterprise.expires_date) {
        plan = 'ENTERPRISE';
        scanLimit = 999999;
      }

      // Update user's subscription
      await this.syncSubscription(app_user_id, {
        revenuecat_user_id: app_user_id,
        plan,
        scanLimit,
        active_subscriptions: Object.keys(entitlements || {}),
      });

      return { success: true };
    } catch (error) {
      console.error('❌ Webhook handling error:', error);
      throw error;
    }
  }

  /**
   * Cancel subscription (for user request)
   */
  async cancelSubscription(userId) {
    try {
      console.log('🚫 Canceling subscription for user:', userId);

      // Reset to FREE plan
      const params = {
        TableName: 'vuln-scanner-users',
        Key: { userId },
        UpdateExpression: `
          SET subscriptionPlan = :plan,
              scanLimit = :limit,
              activeSubscriptions = :subs,
              canceledAt = :now,
              updatedAt = :now
        `,
        ExpressionAttributeValues: {
          ':plan': 'FREE',
          ':limit': 3,
          ':subs': [],
          ':now': new Date().toISOString(),
        },
        ReturnValues: 'ALL_NEW',
      };

      const result = await dynamoDB.send(new UpdateCommand(params));

      return {
        success: true,
        message: 'Subscription canceled successfully',
        user: result.Attributes,
      };
    } catch (error) {
      console.error('❌ Cancel subscription error:', error);
      throw error;
    }
  }
}

module.exports = new SubscriptionService();
