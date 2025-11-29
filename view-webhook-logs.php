<?php
/**
 * View Webhook Logs
 * Simple log viewer to monitor webhook activity
 * 
 * Usage: https://cloudwalls.art/api/view-webhook-logs.php?lines=100
 */

header('Content-Type: text/html; charset=utf-8');

// Security: Only allow from localhost or add authentication
$allowedIPs = ['127.0.0.1', '::1'];
$clientIP = $_SERVER['REMOTE_ADDR'] ?? '';

// Uncomment to restrict access:
// if (!in_array($clientIP, $allowedIPs) && $clientIP !== 'YOUR_SERVER_IP') {
//     die('Access denied');
// }

$lines = isset($_GET['lines']) ? (int)$_GET['lines'] : 50;
$logFile = ini_get('error_log') ?: '/var/log/php/error.log';

// Try alternative log locations
$possibleLogs = [
    $logFile,
    __DIR__ . '/../logs/webhook.log',
    __DIR__ . '/../logs/error.log',
    '/var/log/apache2/error.log',
    '/var/log/nginx/error.log'
];

$logContent = '';
foreach ($possibleLogs as $log) {
    if (file_exists($log) && is_readable($log)) {
        $logContent = shell_exec("tail -n $lines " . escapeshellarg($log) . " 2>/dev/null");
        if ($logContent) {
            $logFile = $log;
            break;
        }
    }
}

if (!$logContent) {
    // Try to get from error_log() output
    $logContent = "Log file not found. Check PHP error_log setting.\n";
    $logContent .= "PHP error_log: " . ini_get('error_log') . "\n";
    $logContent .= "Available logs: " . implode(', ', $possibleLogs);
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Webhook Logs Viewer</title>
    <meta charset="utf-8">
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            margin: 0;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            color: #4ec9b0;
            border-bottom: 2px solid #4ec9b0;
            padding-bottom: 10px;
        }
        .controls {
            background: #252526;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .controls a {
            color: #4ec9b0;
            text-decoration: none;
            margin-right: 15px;
            padding: 5px 10px;
            background: #3c3c3c;
            border-radius: 3px;
        }
        .controls a:hover {
            background: #4c4c4c;
        }
        .log-content {
            background: #1e1e1e;
            border: 1px solid #3c3c3c;
            padding: 15px;
            border-radius: 5px;
            white-space: pre-wrap;
            font-size: 12px;
            line-height: 1.6;
            max-height: 80vh;
            overflow-y: auto;
        }
        .log-line {
            margin: 2px 0;
        }
        .log-webhook { color: #4ec9b0; }
        .log-success { color: #4ec9b0; }
        .log-error { color: #f48771; }
        .log-warning { color: #dcdcaa; }
        .log-info { color: #569cd6; }
        .auto-refresh {
            color: #ce9178;
            font-size: 11px;
            margin-top: 10px;
        }
    </style>
    <script>
        // Auto-refresh every 5 seconds
        setTimeout(function() {
            window.location.reload();
        }, 5000);
    </script>
</head>
<body>
    <div class="container">
        <h1>🔍 Webhook Activity Logs</h1>
        <div class="controls">
            <a href="?lines=50">Last 50 lines</a>
            <a href="?lines=100">Last 100 lines</a>
            <a href="?lines=200">Last 200 lines</a>
            <a href="?lines=500">Last 500 lines</a>
            <span style="color: #858585; margin-left: 20px;">
                Log file: <?php echo htmlspecialchars($logFile); ?>
            </span>
            <span class="auto-refresh">🔄 Auto-refreshing every 5 seconds...</span>
        </div>
        <div class="log-content">
<?php
$lines = explode("\n", $logContent);
foreach ($lines as $line) {
    $class = 'log-line';
    if (strpos($line, '=== Google Play Webhook') !== false) {
        $class .= ' log-webhook';
    } elseif (strpos($line, '✅') !== false || strpos($line, 'success') !== false) {
        $class .= ' log-success';
    } elseif (strpos($line, '❌') !== false || strpos($line, 'error') !== false || strpos($line, 'Error') !== false) {
        $class .= ' log-error';
    } elseif (strpos($line, '⚠️') !== false || strpos($line, 'warning') !== false) {
        $class .= ' log-warning';
    } elseif (strpos($line, 'Notification Type') !== false || strpos($line, 'Subscription') !== false) {
        $class .= ' log-info';
    }
    echo '<div class="' . $class . '">' . htmlspecialchars($line) . '</div>';
}
?>
        </div>
    </div>
</body>
</html>

