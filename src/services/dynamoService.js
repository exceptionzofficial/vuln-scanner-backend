// src/services/dynamoService.js
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  QueryCommand,
  UpdateCommand,
  ScanCommand,
} = require('@aws-sdk/lib-dynamodb');

const client = new DynamoDBClient({
  region: process.env.AWS_REGION || 'ap-south-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const dynamoDB = DynamoDBDocumentClient.from(client);

const TABLES = {
  USERS: 'vuln-scanner-users',
  SCANS: 'vuln-scanner-scans',
};

class DynamoService {
  // ==================== USER OPERATIONS ====================
  
  async createUser(userData) {
    const params = {
      TableName: TABLES.USERS,
      Item: {
        userId: userData.userId,
        email: userData.email.toLowerCase(),
        password: userData.password,
        name: userData.name,
        createdAt: userData.createdAt,
        scansUsed: userData.scansUsed,
        scanLimit: userData.scanLimit,
        lastScanDate: userData.lastScanDate,
      },
    };

    await dynamoDB.send(new PutCommand(params));
    return params.Item;
  }

  async getUserByEmail(email) {
    const params = {
      TableName: TABLES.USERS,
      IndexName: 'EmailIndex',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: {
        ':email': email.toLowerCase(),
      },
    };

    const result = await dynamoDB.send(new QueryCommand(params));
    return result.Items?.[0];
  }

  async getUserById(userId) {
    const params = {
      TableName: TABLES.USERS,
      Key: { userId },
    };

    const result = await dynamoDB.send(new GetCommand(params));
    return result.Item;
  }

  async updateUserScans(userId, scansUsed) {
    const params = {
      TableName: TABLES.USERS,
      Key: { userId },
      UpdateExpression: 'SET scansUsed = :scansUsed, lastScanDate = :lastScanDate',
      ExpressionAttributeValues: {
        ':scansUsed': scansUsed,
        ':lastScanDate': new Date().toISOString(),
      },
      ReturnValues: 'ALL_NEW',
    };

    const result = await dynamoDB.send(new UpdateCommand(params));
    return result.Attributes;
  }

/**
 * Update user's scan limit after subscription purchase
 * Stores expiry date for validation
 */
async updateUserScanLimit(userId, subscriptionData) {
  try {
    const currentUser = await this.getUserById(userId);
    
    const now = new Date().toISOString();
    let scansUsed = currentUser?.scansUsed || 0;
    
    // Check if this is a new subscription or renewal
    const isNewSubscription = !currentUser?.subscriptionPlan || 
                               currentUser?.subscriptionPlan === 'FREE' ||
                               currentUser?.subscriptionPlan !== subscriptionData.plan;
    
    // Reset scans if new subscription or plan upgrade
    if (isNewSubscription) {
      scansUsed = 0;
      console.log('🔄 Resetting scansUsed to 0 (new subscription/upgrade)');
    }
    
    // Calculate dates
    const nextResetDate = new Date();
    nextResetDate.setDate(nextResetDate.getDate() + 30);
    
    // Use expiry date from RevenueCat if available
    const expiryDate = subscriptionData.expiryDate || nextResetDate.toISOString();
    
    const params = {
      TableName: TABLES.USERS,
      Key: { userId },
      UpdateExpression: `
        SET subscriptionPlan = :plan,
            scanLimit = :limit,
            scansUsed = :scansUsed,
            subscriptionStartDate = :startDate,
            subscriptionExpiryDate = :expiryDate,
            nextResetDate = :resetDate,
            isSubscriptionActive = :isActive,
            updatedAt = :now
      `,
      ExpressionAttributeValues: {
        ':plan': subscriptionData.plan,
        ':limit': subscriptionData.scanLimit,
        ':scansUsed': scansUsed,
        ':startDate': now,
        ':expiryDate': expiryDate,
        ':resetDate': nextResetDate.toISOString(),
        ':isActive': subscriptionData.isActive !== false,
        ':now': now,
      },
      ReturnValues: 'ALL_NEW',
    };

    const result = await dynamoDB.send(new UpdateCommand(params));
    console.log('✅ User subscription updated:', {
      plan: result.Attributes.subscriptionPlan,
      scanLimit: result.Attributes.scanLimit,
      expiryDate: result.Attributes.subscriptionExpiryDate,
      isActive: result.Attributes.isSubscriptionActive,
    });
    
    return result.Attributes;
  } catch (error) {
    console.error('❌ Update scan limit error:', error);
    throw error;
  }
}

/**
 * Check and reset scans if billing period renewed
 */
async checkAndResetScans(userId) {
  try {
    const user = await this.getUserById(userId);
    
    if (!user || !user.nextResetDate) {
      return user;
    }
    
    const now = new Date();
    const resetDate = new Date(user.nextResetDate);
    
    // If reset date has passed, reset scans
    if (now >= resetDate) {
      console.log('🔄 Resetting scans for user (billing period renewed)');
      
      // Calculate next reset date (30 days from now)
      const nextResetDate = new Date();
      nextResetDate.setDate(nextResetDate.getDate() + 30);
      
      const params = {
        TableName: TABLES.USERS,
        Key: { userId },
        UpdateExpression: `
          SET scansUsed = :zero,
              nextResetDate = :resetDate,
              lastResetDate = :now,
              updatedAt = :now
        `,
        ExpressionAttributeValues: {
          ':zero': 0,
          ':resetDate': nextResetDate.toISOString(),
          ':now': now.toISOString(),
        },
        ReturnValues: 'ALL_NEW',
      };
      
      const result = await dynamoDB.send(new UpdateCommand(params));
      return result.Attributes;
    }
    
    return user;
  } catch (error) {
    console.error('❌ Check and reset scans error:', error);
    return user;
  }
}



  // ==================== SCAN OPERATIONS ====================
  
  async createScan(scanData) {
    const params = {
      TableName: TABLES.SCANS,
      Item: {
        scanId: scanData.scanId,
        userId: scanData.userId,
        targetUrl: scanData.targetUrl,
        scanTime: scanData.scanTime,
        vulnerabilitiesFound: scanData.vulnerabilitiesFound,
        riskLevel: scanData.riskLevel,
        riskScore: scanData.riskScore,
        vulnerabilities: scanData.vulnerabilities,
        summary: scanData.summary,
      },
    };

    await dynamoDB.send(new PutCommand(params));
    return params.Item;
  }

async getUserScans(userId, limit = 20) {
  const params = {
    TableName: TABLES.SCANS,
    IndexName: 'UserIdIndex', // Need GSI on userId
    KeyConditionExpression: 'userId = :userId',
    ExpressionAttributeValues: {
      ':userId': userId,
    },
    Limit: limit,
    ScanIndexForward: false, // Latest first
  };

  try {
    const result = await dynamoDB.send(new QueryCommand(params));
    return result.Items || [];
  } catch (error) {
    console.error('Get user scans error:', error);
    return [];
  }
}
  async getScanById(scanId, userId) {
    const params = {
      TableName: TABLES.SCANS,
      Key: {
        scanId,
        userId,
      },
    };

    const result = await dynamoDB.send(new GetCommand(params));
    return result.Item;
  }


async updateUserSubscription(userId, subscriptionData) {
  const params = {
    TableName: TABLES.USERS,
    Key: { userId },
    UpdateExpression: `
      SET subscriptionPlan = :plan,
          scanLimit = :limit,
          revenuecatUserId = :rcUserId,
          updatedAt = :now
    `,
    ExpressionAttributeValues: {
      ':plan': subscriptionData.plan,
      ':limit': subscriptionData.scanLimit,
      ':rcUserId': subscriptionData.revenuecat_user_id || userId,
      ':now': new Date().toISOString(),
    },
    ReturnValues: 'ALL_NEW',
  };

  try {
    const result = await dynamoDB.send(new UpdateCommand(params));
    return result.Attributes;
  } catch (error) {
    console.error('Update subscription error:', error);
    throw error;
  }
}

/**
 * Get user's subscription status
 */
async getUserSubscription(userId) {
  const params = {
    TableName: TABLES.USERS,
    Key: { userId },
  };

  try {
    const result = await dynamoDB.send(new GetCommand(params));
    if (!result.Item) {
      return {
        subscriptionPlan: 'FREE',
        scanLimit: 3,
        scansUsed: 0,
      };
    }
    return result.Item;
  } catch (error) {
    console.error('Get subscription error:', error);
    throw error;
  }
}

}  // ✅ ONLY ONE CLOSING BRACE

module.exports = new DynamoService();