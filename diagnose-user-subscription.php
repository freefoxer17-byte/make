<?php
/**
 * Diagnose User Subscription
 * Checks database state and provides manual fix option
 */

header('Content-Type: text/html; charset=utf-8');

$userId = $_GET['user_id'] ?? '3cJImbaENeTpJ1jbZTzOb5umasd2';

require_once __DIR__ . '/../config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    echo "<h1>Diagnostic Report for User: $userId</h1>";
    
    // Check app_users
    $userQuery = "SELECT firebase_uid, email, display_name FROM app_users WHERE firebase_uid = ? LIMIT 1";
    $userStmt = $db->prepare($userQuery);
    $userStmt->execute([$userId]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        echo "<p style='color: red;'>❌ User not found in app_users table</p>";
        exit;
    }
    
    echo "<h2>User Info:</h2>";
    echo "<pre>" . json_encode($user, JSON_PRETTY_PRINT) . "</pre>";
    
    $firebaseUid = $user['firebase_uid'];
    
    // Check user_subscriptions
    $userSubQuery = "SELECT * FROM user_subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1";
    $userSubStmt = $db->prepare($userSubQuery);
    $userSubStmt->execute([$firebaseUid]);
    $userSub = $userSubStmt->fetch(PDO::FETCH_ASSOC);
    
    echo "<h2>user_subscriptions Table:</h2>";
    if ($userSub) {
        echo "<pre>" . json_encode($userSub, JSON_PRETTY_PRINT) . "</pre>";
    } else {
        echo "<p style='color: orange;'>⚠️ No record in user_subscriptions</p>";
    }
    
    // Check ai_subscriptions
    $aiSubQuery = "SELECT * FROM ai_subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1";
    $aiSubStmt = $db->prepare($aiSubQuery);
    $aiSubStmt->execute([$firebaseUid]);
    $aiSub = $aiSubStmt->fetch(PDO::FETCH_ASSOC);
    
    echo "<h2>ai_subscriptions Table:</h2>";
    if ($aiSub) {
        echo "<pre>" . json_encode($aiSub, JSON_PRETTY_PRINT) . "</pre>";
    } else {
        echo "<p style='color: orange;'>⚠️ No record in ai_subscriptions</p>";
    }
    
    // Check google_play_purchases
    $purchaseQuery = "SELECT * FROM google_play_purchases WHERE user_id = ? ORDER BY id DESC";
    $purchaseStmt = $db->prepare($purchaseQuery);
    $purchaseStmt->execute([$firebaseUid]);
    $purchases = $purchaseStmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "<h2>google_play_purchases Table:</h2>";
    if (!empty($purchases)) {
        echo "<p>Found " . count($purchases) . " purchase(s):</p>";
        echo "<pre>" . json_encode($purchases, JSON_PRETTY_PRINT) . "</pre>";
    } else {
        echo "<p style='color: red;'>❌ No purchase tokens found! This is why webhook can't find the user.</p>";
    }
    
    // Manual fix option
    echo "<hr>";
    echo "<h2>Manual Fix Options:</h2>";
    
    if (isset($_GET['action']) && $_GET['action'] === 'downgrade') {
        echo "<p style='color: green;'>🔄 Downgrading user to free...</p>";
        
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
        $userSubRows = $updateUserSubStmt->rowCount();
        
        // Downgrade ai_subscriptions
        $updateAiSubQuery = "UPDATE ai_subscriptions 
                            SET subscription_tier = 'free',
                                is_active = 0,
                                auto_renew = 0,
                                subscription_start = NULL,
                                subscription_end = NULL,
                                canceled_at = NOW(),
                                cancel_reason = 'Manually downgraded - canceled from Google Play'
                            WHERE user_id = ?";
        $updateAiSubStmt = $db->prepare($updateAiSubQuery);
        $updateAiSubStmt->execute([$firebaseUid]);
        $aiSubRows = $updateAiSubStmt->rowCount();
        
        // Update generation limits
        $updateLimitsQuery = "UPDATE ai_generation_limits 
                             SET tier = 'free',
                                 daily_limit = 5,
                                 monthly_limit = 150
                             WHERE user_id = ?";
        $updateLimitsStmt = $db->prepare($updateLimitsQuery);
        $updateLimitsStmt->execute([$firebaseUid]);
        $limitsRows = $updateLimitsStmt->rowCount();
        
        echo "<p style='color: green;'>✅ Updated:</p>";
        echo "<ul>";
        echo "<li>user_subscriptions: $userSubRows row(s)</li>";
        echo "<li>ai_subscriptions: $aiSubRows row(s)</li>";
        echo "<li>ai_generation_limits: $limitsRows row(s)</li>";
        echo "</ul>";
        
        echo "<p><strong>✅ User has been downgraded to free plan!</strong></p>";
        echo "<p><a href='?user_id=$userId'>Refresh to see updated state</a></p>";
    } else {
        echo "<p><strong>If user canceled from Google Play, click below to manually downgrade:</strong></p>";
        echo "<p><a href='?user_id=$userId&action=downgrade' style='background: red; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>🔴 MANUALLY DOWNGRADE TO FREE</a></p>";
    }
    
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ Error: " . htmlspecialchars($e->getMessage()) . "</p>";
}
?>

