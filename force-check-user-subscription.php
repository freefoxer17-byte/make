<?php
/**
 * Force Check User Subscription Status
 * Manually checks and updates a specific user's subscription from Google Play
 * 
 * Usage: https://cloudwalls.art/api/force-check-user-subscription.php?user_id=3cJImbaENeTpJ1jbZTzOb5umasd2
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../config/database.php';

$userId = $_GET['user_id'] ?? null;

if (!$userId) {
    echo json_encode(['success' => false, 'error' => 'User ID required']);
    exit;
}

try {
    $database = new Database();
    $db = $database->getConnection();
    
    error_log("🔍 Force checking subscription for user: $userId");
    
    // Get user's Firebase UID
    $userQuery = "SELECT firebase_uid FROM app_users WHERE firebase_uid = ? OR id = ? LIMIT 1";
    $userStmt = $db->prepare($userQuery);
    $userStmt->execute([$userId, $userId]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        echo json_encode(['success' => false, 'error' => 'User not found']);
        exit;
    }
    
    $firebaseUid = $user['firebase_uid'];
    
    // Get current database state
    $currentStateQuery = "SELECT 
        us.subscription_tier as user_sub_tier,
        us.is_active as user_sub_active,
        ai.subscription_tier as ai_sub_tier,
        ai.is_active as ai_sub_active,
        ai.auto_renew,
        ai.canceled_at
    FROM user_subscriptions us
    LEFT JOIN ai_subscriptions ai ON us.user_id = ai.user_id
    WHERE us.user_id = ?
    LIMIT 1";
    $currentStmt = $db->prepare($currentStateQuery);
    $currentStmt->execute([$firebaseUid]);
    $currentState = $currentStmt->fetch(PDO::FETCH_ASSOC);
    
    echo "<h2>Current Database State:</h2>";
    echo "<pre>" . json_encode($currentState, JSON_PRETTY_PRINT) . "</pre><br>";
    
    // Get all purchase tokens for this user
    $purchaseQuery = "SELECT product_id, purchase_token, order_id 
                     FROM google_play_purchases 
                     WHERE user_id = ? 
                     ORDER BY id DESC";
    $purchaseStmt = $db->prepare($purchaseQuery);
    $purchaseStmt->execute([$firebaseUid]);
    $purchases = $purchaseStmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (empty($purchases)) {
        echo json_encode([
            'success' => false,
            'error' => 'No purchase tokens found for user',
            'current_state' => $currentState
        ]);
        exit;
    }
    
    echo "<h2>Found " . count($purchases) . " purchase(s):</h2>";
    echo "<pre>" . json_encode($purchases, JSON_PRETTY_PRINT) . "</pre><br>";
    
    $updated = false;
    $results = [];
    
    foreach ($purchases as $purchase) {
        $productId = $purchase['product_id'];
        $token = $purchase['purchase_token'];
        
        echo "<h3>Checking: $productId</h3>";
        echo "<p>Token: " . substr($token, 0, 30) . "...</p>";
        
        // Get subscription status from Google Play
        $subscriptionData = getSubscriptionFromGooglePlay($productId, $token);
        
        if ($subscriptionData) {
            $autoRenewing = $subscriptionData['autoRenewing'] ?? false;
            $expiryTimeMillis = $subscriptionData['expiryTimeMillis'] ?? null;
            $cancelReason = $subscriptionData['cancelReason'] ?? null;
            
            echo "<p><strong>Google Play Status:</strong></p>";
            echo "<ul>";
            echo "<li>autoRenewing: " . ($autoRenewing ? 'true' : 'false') . "</li>";
            echo "<li>expiryTimeMillis: " . ($expiryTimeMillis ?? 'null') . "</li>";
            echo "<li>cancelReason: " . ($cancelReason ?? 'null') . "</li>";
            echo "</ul>";
            
            $results[] = [
                'product_id' => $productId,
                'auto_renewing' => $autoRenewing,
                'expiry_time' => $expiryTimeMillis ? date('Y-m-d H:i:s', $expiryTimeMillis / 1000) : null,
                'cancel_reason' => $cancelReason
            ];
            
            // If canceled (autoRenewing = false), downgrade immediately
            if (!$autoRenewing) {
                echo "<p style='color: red;'><strong>⚠️ Subscription is CANCELED - Downgrading to free...</strong></p>";
                
                // Downgrade ai_subscriptions
                $updateAiSubQuery = "UPDATE ai_subscriptions 
                                   SET subscription_tier = 'free',
                                       is_active = 0,
                                       auto_renew = 0,
                                       subscription_start = NULL,
                                       subscription_end = NULL,
                                       canceled_at = NOW(),
                                       cancel_reason = ?
                                   WHERE user_id = ?";
                $updateAiSubStmt = $db->prepare($updateAiSubQuery);
                $updateAiSubStmt->execute([$cancelReason ?? 'User canceled via Google Play', $firebaseUid]);
                
                // Downgrade user_subscriptions
                $updateUserSubQuery = "UPDATE user_subscriptions 
                                      SET subscription_tier = 'free',
                                          is_active = 0,
                                          subscription_start = NULL,
                                          subscription_end = NULL,
                                          subscription_credit_balance = 0
                                      WHERE user_id = ?";
                $updateUserSubStmt = $db->prepare($updateUserSubQuery);
                $updateUserSubStmt->execute([$firebaseUid]);
                
                // Update generation limits
                $updateLimitsQuery = "UPDATE ai_generation_limits 
                                     SET tier = 'free',
                                         daily_limit = 5,
                                         monthly_limit = 150
                                     WHERE user_id = ?";
                $updateLimitsStmt = $db->prepare($updateLimitsQuery);
                $updateLimitsStmt->execute([$firebaseUid]);
                
                $updated = true;
                echo "<p style='color: green;'><strong>✅ User downgraded to free plan!</strong></p>";
            } else {
                echo "<p style='color: green;'>Subscription is active and renewing</p>";
            }
        } else {
            echo "<p style='color: orange;'>⚠️ Could not get data from Google Play API</p>";
            $results[] = [
                'product_id' => $productId,
                'error' => 'Could not fetch from Google Play API'
            ];
        }
    }
    
    // Get updated state
    $updatedStateQuery = "SELECT 
        us.subscription_tier as user_sub_tier,
        us.is_active as user_sub_active,
        ai.subscription_tier as ai_sub_tier,
        ai.is_active as ai_sub_active,
        ai.auto_renew,
        ai.canceled_at
    FROM user_subscriptions us
    LEFT JOIN ai_subscriptions ai ON us.user_id = ai.user_id
    WHERE us.user_id = ?
    LIMIT 1";
    $updatedStmt = $db->prepare($updatedStateQuery);
    $updatedStmt->execute([$firebaseUid]);
    $updatedState = $updatedStmt->fetch(PDO::FETCH_ASSOC);
    
    echo "<h2>Updated Database State:</h2>";
    echo "<pre>" . json_encode($updatedState, JSON_PRETTY_PRINT) . "</pre>";
    
    echo json_encode([
        'success' => true,
        'user_id' => $firebaseUid,
        'updated' => $updated,
        'google_play_status' => $results,
        'current_state' => $currentState,
        'updated_state' => $updatedState
    ], JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    error_log("❌ Error: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

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
            error_log("⚠️ Failed to get subscription data: HTTP $httpCode");
            return null;
        }
        
        return json_decode($response, true);
        
    } catch (Exception $e) {
        error_log("❌ Error getting subscription data: " . $e->getMessage());
        return null;
    }
}

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

