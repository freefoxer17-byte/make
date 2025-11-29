<?php
/**
 * Check Expiring Subscriptions - Cron Job
 * This script should be run daily to check and update expiring subscriptions
 * 
 * Setup cron job:
 * 0 0 * * * /usr/bin/php /path/to/webadmin35/api/check-expiring-subscriptions.php
 * 
 * Or call via HTTP:
 * https://cloudwalls.art/api/check-expiring-subscriptions.php
 */

// Start output buffering
ob_start();

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    error_log("=== Starting Expiring Subscriptions Check ===");
    
    // Get all active subscriptions that are expiring soon (within 1 day) or expired
    $today = date('Y-m-d');
    $tomorrow = date('Y-m-d', strtotime('+1 day'));
    
    $query = "SELECT 
                us.user_id,
                us.subscription_tier,
                us.subscription_end,
                us.auto_renew,
                gpp.product_id,
                gpp.purchase_token
              FROM user_subscriptions us
              INNER JOIN google_play_purchases gpp ON us.user_id = gpp.user_id
              WHERE us.is_active = 1
                AND us.subscription_tier != 'free'
                AND us.subscription_end IS NOT NULL
                AND us.subscription_end <= ?
              ORDER BY us.subscription_end ASC";
    
    $stmt = $db->prepare($query);
    $stmt->execute([$tomorrow]);
    $expiringSubscriptions = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    error_log("Found " . count($expiringSubscriptions) . " expiring subscriptions");
    
    $updated = 0;
    $expired = 0;
    $errors = 0;
    
    foreach ($expiringSubscriptions as $subscription) {
        $userId = $subscription['user_id'];
        $productId = $subscription['product_id'];
        $purchaseToken = $subscription['purchase_token'];
        $subscriptionEnd = $subscription['subscription_end'];
        $autoRenew = $subscription['auto_renew'];
        
        try {
            // Check subscription status from Google Play
            $subscriptionData = getSubscriptionFromGooglePlay($productId, $purchaseToken);
            
            if ($subscriptionData) {
                $autoRenewing = $subscriptionData['autoRenewing'] ?? false;
                $expiryTimeMillis = $subscriptionData['expiryTimeMillis'] ?? null;
                $expiryDate = $expiryTimeMillis ? date('Y-m-d H:i:s', $expiryTimeMillis / 1000) : null;
                $isExpired = $expiryTimeMillis && ($expiryTimeMillis / 1000) < time();
                
                if ($isExpired && !$autoRenewing) {
                    // Subscription expired and not renewing - downgrade to free
                    $updateQuery = "UPDATE user_subscriptions 
                                   SET subscription_tier = 'free',
                                       is_active = 0,
                                       subscription_start = NULL,
                                       subscription_end = NULL,
                                       subscription_credit_balance = 0
                                   WHERE user_id = ?";
                    $updateStmt = $db->prepare($updateQuery);
                    $updateStmt->execute([$userId]);
                    
                    $updateAiSubQuery = "UPDATE ai_subscriptions 
                                        SET subscription_tier = 'free',
                                            is_active = 0,
                                            auto_renew = 0,
                                            subscription_start = NULL,
                                            subscription_end = NULL
                                        WHERE user_id = ?";
                    $updateAiSubStmt = $db->prepare($updateAiSubQuery);
                    $updateAiSubStmt->execute([$userId]);
                    
                    $expired++;
                    error_log("✅ Expired subscription for user: $userId");
                } elseif ($autoRenewing && $expiryDate) {
                    // Subscription renewed - update expiry date
                    $updateQuery = "UPDATE user_subscriptions 
                                   SET subscription_end = ?,
                                       auto_renew = 1
                                   WHERE user_id = ?";
                    $updateStmt = $db->prepare($updateQuery);
                    $updateStmt->execute([$expiryDate, $userId]);
                    
                    $updateAiSubQuery = "UPDATE ai_subscriptions 
                                       SET subscription_end = ?,
                                           auto_renew = 1,
                                           canceled_at = NULL
                                       WHERE user_id = ?";
                    $updateAiSubStmt = $db->prepare($updateAiSubQuery);
                    $updateAiSubStmt->execute([$expiryDate, $userId]);
                    
                    $updated++;
                    error_log("✅ Updated renewed subscription for user: $userId");
                } elseif (!$autoRenewing) {
                    // ✅ Subscription canceled - IMMEDIATELY downgrade to free (don't wait for expiry)
                    $updateQuery = "UPDATE user_subscriptions 
                                   SET subscription_tier = 'free',
                                       is_active = 0,
                                       subscription_start = NULL,
                                       subscription_end = NULL,
                                       subscription_credit_balance = 0
                                   WHERE user_id = ?";
                    $updateStmt = $db->prepare($updateQuery);
                    $updateStmt->execute([$userId]);
                    
                    $updateAiSubQuery = "UPDATE ai_subscriptions 
                                       SET subscription_tier = 'free',
                                           is_active = 0,
                                           auto_renew = 0,
                                           subscription_start = NULL,
                                           subscription_end = NULL,
                                           canceled_at = COALESCE(canceled_at, NOW())
                                       WHERE user_id = ?";
                    $updateAiSubStmt = $db->prepare($updateAiSubQuery);
                    $updateAiSubStmt->execute([$userId]);
                    
                    // Update generation limits
                    $updateLimitsQuery = "UPDATE ai_generation_limits 
                                         SET tier = 'free',
                                             daily_limit = 5,
                                             monthly_limit = 150
                                         WHERE user_id = ?";
                    $updateLimitsStmt = $db->prepare($updateLimitsQuery);
                    $updateLimitsStmt->execute([$userId]);
                    
                    $updated++;
                    error_log("✅ IMMEDIATELY downgraded canceled subscription to free for user: $userId");
                }
            } else {
                // Could not get data from Google Play - check if already expired
                if (strtotime($subscriptionEnd) < time() && !$autoRenew) {
                    // Expired and not renewing - downgrade
                    $updateQuery = "UPDATE user_subscriptions 
                                   SET subscription_tier = 'free',
                                       is_active = 0,
                                       subscription_start = NULL,
                                       subscription_end = NULL,
                                       subscription_credit_balance = 0
                                   WHERE user_id = ?";
                    $updateStmt = $db->prepare($updateQuery);
                    $updateStmt->execute([$userId]);
                    
                    $updateAiSubQuery = "UPDATE ai_subscriptions 
                                        SET subscription_tier = 'free',
                                            is_active = 0,
                                            auto_renew = 0,
                                            subscription_start = NULL,
                                            subscription_end = NULL
                                        WHERE user_id = ?";
                    $updateAiSubStmt = $db->prepare($updateAiSubQuery);
                    $updateAiSubStmt->execute([$userId]);
                    
                    $expired++;
                    error_log("✅ Expired subscription (no Google Play data) for user: $userId");
                }
            }
        } catch (Exception $e) {
            $errors++;
            error_log("❌ Error checking subscription for user $userId: " . $e->getMessage());
        }
    }
    
    error_log("=== Expiring Subscriptions Check Complete ===");
    error_log("Updated: $updated, Expired: $expired, Errors: $errors");
    
    ob_end_clean();
    echo json_encode([
        'success' => true,
        'checked' => count($expiringSubscriptions),
        'updated' => $updated,
        'expired' => $expired,
        'errors' => $errors
    ]);
    
} catch (Exception $e) {
    ob_end_clean();
    error_log("❌ Check expiring subscriptions error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
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

