<?php
/**
 * Check Subscription Status from Google Play API
 * This endpoint verifies subscription status directly from Google Play
 * 
 * Usage: POST with user_id and purchase_token (optional)
 * If purchase_token not provided, checks all active subscriptions for user
 */

// Start output buffering
ob_start();

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET');
header('Access-Control-Allow-Headers: Content-Type');

require_once __DIR__ . '/../config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    $input = json_decode(file_get_contents('php://input'), true);
    $userId = $input['user_id'] ?? $_GET['user_id'] ?? null;
    $purchaseToken = $input['purchase_token'] ?? $_GET['purchase_token'] ?? null;
    
    if (!$userId) {
        ob_end_clean();
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'User ID required']);
        exit;
    }
    
    // Get user's Firebase UID
    $userQuery = "SELECT firebase_uid FROM app_users WHERE firebase_uid = ? OR id = ? LIMIT 1";
    $userStmt = $db->prepare($userQuery);
    $userStmt->execute([$userId, $userId]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        ob_end_clean();
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'User not found']);
        exit;
    }
    
    $firebaseUid = $user['firebase_uid'];
    
    // Get purchase tokens for this user
    if ($purchaseToken) {
        // Check specific purchase token
        $purchaseQuery = "SELECT product_id, purchase_token, order_id 
                         FROM google_play_purchases 
                         WHERE user_id = ? AND purchase_token = ? 
                         ORDER BY id DESC LIMIT 1";
        $purchaseStmt = $db->prepare($purchaseQuery);
        $purchaseStmt->execute([$firebaseUid, $purchaseToken]);
        $purchases = $purchaseStmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        // Check all active purchases for user
        $purchaseQuery = "SELECT product_id, purchase_token, order_id 
                         FROM google_play_purchases 
                         WHERE user_id = ? 
                         ORDER BY id DESC";
        $purchaseStmt = $db->prepare($purchaseQuery);
        $purchaseStmt->execute([$firebaseUid]);
        $purchases = $purchaseStmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    if (empty($purchases)) {
        ob_end_clean();
        echo json_encode([
            'success' => true,
            'subscriptions' => [],
            'message' => 'No purchases found for user'
        ]);
        exit;
    }
    
    $subscriptionStatuses = [];
    
    foreach ($purchases as $purchase) {
        $productId = $purchase['product_id'];
        $token = $purchase['purchase_token'];
        
        // Get subscription status from Google Play
        $subscriptionData = getSubscriptionFromGooglePlay($productId, $token);
        
        if ($subscriptionData) {
            $autoRenewing = $subscriptionData['autoRenewing'] ?? false;
            $expiryTimeMillis = $subscriptionData['expiryTimeMillis'] ?? null;
            $cancelReason = $subscriptionData['cancelReason'] ?? null;
            $canceledStateContext = $subscriptionData['canceledStateContext'] ?? null;
            
            $expiryDate = $expiryTimeMillis ? date('Y-m-d H:i:s', $expiryTimeMillis / 1000) : null;
            $isExpired = $expiryTimeMillis && ($expiryTimeMillis / 1000) < time();
            
            $subscriptionStatuses[] = [
                'product_id' => $productId,
                'purchase_token' => substr($token, 0, 20) . '...',
                'order_id' => $purchase['order_id'],
                'auto_renewing' => $autoRenewing,
                'expiry_date' => $expiryDate,
                'is_expired' => $isExpired,
                'cancel_reason' => $cancelReason,
                'canceled_state' => $canceledStateContext,
                'status' => $isExpired ? 'expired' : ($autoRenewing ? 'active' : 'canceled')
            ];
            
            // Update database if status changed
            updateSubscriptionStatus($db, $firebaseUid, $productId, $subscriptionData);
        }
    }
    
    ob_end_clean();
    echo json_encode([
        'success' => true,
        'subscriptions' => $subscriptionStatuses,
        'user_id' => $firebaseUid
    ]);
    
} catch (Exception $e) {
    ob_end_clean();
    error_log("❌ Check subscription status error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

/**
 * Update subscription status in database based on Google Play data
 */
function updateSubscriptionStatus($db, $userId, $productId, $subscriptionData) {
    $autoRenewing = $subscriptionData['autoRenewing'] ?? false;
    $expiryTimeMillis = $subscriptionData['expiryTimeMillis'] ?? null;
    $cancelReason = $subscriptionData['cancelReason'] ?? null;
    
    $expiryDate = $expiryTimeMillis ? date('Y-m-d H:i:s', $expiryTimeMillis / 1000) : null;
    $isExpired = $expiryTimeMillis && ($expiryTimeMillis / 1000) < time();
    
    // Determine plan key from product ID
    $planKey = 'free';
    if (strpos($productId, 'premium') !== false) {
        $planKey = 'premium';
    } elseif (strpos($productId, 'pro') !== false) {
        $planKey = 'pro';
    } elseif (strpos($productId, 'starter') !== false) {
        $planKey = 'starter';
    }
    
    if ($isExpired) {
        // Subscription expired - downgrade to free
        $updateQuery = "UPDATE ai_subscriptions 
                       SET subscription_tier = 'free',
                           is_active = 0,
                           auto_renew = 0,
                           subscription_end = ?,
                           canceled_at = NOW()
                       WHERE user_id = ?";
        $updateStmt = $db->prepare($updateQuery);
        $updateStmt->execute([$expiryDate, $userId]);
        
        $updateUserSubQuery = "UPDATE user_subscriptions 
                              SET subscription_tier = 'free',
                                  is_active = 0,
                                  subscription_end = ?,
                                  subscription_credit_balance = 0
                              WHERE user_id = ?";
        $updateUserSubStmt = $db->prepare($updateUserSubQuery);
        $updateUserSubStmt->execute([$expiryDate, $userId]);
        
        error_log("✅ Updated expired subscription for user: $userId");
    } elseif (!$autoRenewing) {
        // Subscription canceled but not expired yet
        // ✅ Subscription canceled - IMMEDIATELY downgrade to free
        $updateQuery = "UPDATE ai_subscriptions 
                       SET subscription_tier = 'free',
                           is_active = 0,
                           auto_renew = 0,
                           subscription_start = NULL,
                           subscription_end = NULL,
                           canceled_at = COALESCE(canceled_at, NOW()),
                           cancel_reason = COALESCE(?, cancel_reason)
                       WHERE user_id = ?";
        $updateStmt = $db->prepare($updateQuery);
        $updateStmt->execute([$cancelReason, $userId]);
        
        // Also update user_subscriptions
        $updateUserSubQuery = "UPDATE user_subscriptions 
                              SET subscription_tier = 'free',
                                  is_active = 0,
                                  subscription_start = NULL,
                                  subscription_end = NULL,
                                  subscription_credit_balance = 0
                              WHERE user_id = ?";
        $updateUserSubStmt = $db->prepare($updateUserSubQuery);
        $updateUserSubStmt->execute([$userId]);
        
        // Update generation limits
        $updateLimitsQuery = "UPDATE ai_generation_limits 
                             SET tier = 'free',
                                 daily_limit = 5,
                                 monthly_limit = 150
                             WHERE user_id = ?";
        $updateLimitsStmt = $db->prepare($updateLimitsQuery);
        $updateLimitsStmt->execute([$userId]);
        
        error_log("✅ IMMEDIATELY downgraded canceled subscription to free for user: $userId");
    } else {
        // Subscription is active and renewing
        $updateQuery = "UPDATE ai_subscriptions 
                       SET auto_renew = 1,
                           subscription_end = ?,
                           canceled_at = NULL,
                           cancel_reason = NULL,
                           is_active = 1
                       WHERE user_id = ?";
        $updateStmt = $db->prepare($updateQuery);
        $updateStmt->execute([$expiryDate, $userId]);
        
        error_log("✅ Updated active subscription for user: $userId");
    }
}

/**
 * Get subscription data from Google Play API
 */
function getSubscriptionFromGooglePlay($subscriptionId, $purchaseToken) {
    $credentialsPath = __DIR__ . '/../config/google-play-service-account.json';
    
    if (!file_exists($credentialsPath)) {
        return null;
    }
    
    try {
        $credentials = json_decode(file_get_contents($credentialsPath), true);
        $packageName = 'com.atlastech.a3dwallpaper4k';
        
        $accessToken = getGoogleAccessToken($credentials);
        
        $apiUrl = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/{$packageName}/purchases/subscriptions/{$subscriptionId}/tokens/{$purchaseToken}";
        
        $ch = curl_init($apiUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/json'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            return null;
        }
        
        return json_decode($response, true);
        
    } catch (Exception $e) {
        error_log("❌ Error getting subscription data: " . $e->getMessage());
        return null;
    }
}

/**
 * Get Google Access Token
 */
function getGoogleAccessToken($credentials) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'RS256']);
    $now = time();
    $payload = json_encode([
        'iss' => $credentials['client_email'],
        'scope' => 'https://www.googleapis.com/auth/androidpublisher',
        'aud' => 'https://oauth2.googleapis.com/token',
        'iat' => $now,
        'exp' => $now + 3600
    ]);
    
    $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    
    $signature = '';
    $privateKey = openssl_pkey_get_private($credentials['private_key']);
    openssl_sign($base64Header . '.' . $base64Payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);
    $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    $jwt = $base64Header . '.' . $base64Payload . '.' . $base64Signature;
    
    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $jwt
    ]));
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception('Failed to get access token: HTTP ' . $httpCode);
    }
    
    $data = json_decode($response, true);
    return $data['access_token'] ?? null;
}
?>

