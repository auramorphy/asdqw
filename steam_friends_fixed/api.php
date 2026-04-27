<?php
declare(strict_types=1);

/**
 * API для добавления в друзья. Работает ПО ОДНОМУ АККАУНТУ за запрос.
 * JS вызывает в цикле — никакого стриминга, никаких проблем с буферами.
 *
 * POST action=add_one & account_id=5 & target_ids[]=76561...&target_ids[]=76561...
 *   → добавляет друзей от одного аккаунта, возвращает JSON результат
 *
 * POST action=check_one & account_id=5 & all_steam_ids[]=76561...
 *   → логинится, проверяет кто из all_steam_ids уже в друзьях
 *
 * GET action=get_accounts
 *   → список аккаунтов
 *
 * GET/POST action=get_cache
 *   → кэшированные данные о дружбе
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache');

// --- Bootstrap ---
$projectRoot = dirname(__DIR__);
for ($dir = __DIR__, $i = 0; $i < 6; $i++, $dir = dirname($dir)) {
    $candidate = dirname($dir);
    if (file_exists($candidate . '/config.php') && (file_exists($candidate . '/db.php') || is_dir($candidate . '/steamtopup'))) {
        $projectRoot = $candidate;
        break;
    }
}

try {
    if (file_exists($projectRoot . '/config.php')) require_once $projectRoot . '/config.php';
    if (file_exists($projectRoot . '/db.php'))     require_once $projectRoot . '/db.php';
    require_once __DIR__ . '/lib/SteamFriendManager.php';

    $pdo = function_exists('db') ? db() : null;
    if (!$pdo && defined('DB_HOST')) {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER, DB_PASS,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
    }
    if (!$pdo) throw new RuntimeException('Нет подключения к БД');
} catch (Throwable $e) {
    die(json_encode(['ok' => false, 'error' => 'Bootstrap: ' . $e->getMessage()]));
}

$logDir  = __DIR__ . '/logs';
$manager = new SteamFriendManager($logDir, $pdo);
$action  = $_GET['action'] ?? $_POST['action'] ?? '';
$cacheFile = $logDir . '/friend_cache.json';

set_time_limit(300);

// ============================================================
// GET ACCOUNTS — список аккаунтов
// ============================================================
if ($action === 'get_accounts') {
    try {
        $all = $manager->getAllAccounts();
        echo json_encode(['ok' => true, 'accounts' => $all]);
    } catch (Throwable $e) {
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// ============================================================
// GET CACHE — кэшированные данные о дружбе
// ============================================================
if ($action === 'get_cache') {
    $cache = is_file($cacheFile) ? json_decode(file_get_contents($cacheFile), true) : [];
    echo json_encode(['ok' => true, 'cache' => $cache ?: []]);
    exit;
}

// ============================================================
// ADD_ONE — добавить друзей от одного аккаунта
// ============================================================
if ($action === 'add_one') {
    $accountId = (int)($_POST['account_id'] ?? 0);
    $targetIds = $_POST['target_ids'] ?? [];

    if (!$accountId || empty($targetIds)) {
        die(json_encode(['ok' => false, 'error' => 'account_id и target_ids[] обязательны']));
    }

    // Найти аккаунт
    $accounts = $manager->getAccounts();
    $account  = null;
    foreach ($accounts as $a) {
        if ((int)$a['id'] === $accountId) { $account = $a; break; }
    }
    if (!$account) {
        die(json_encode(['ok' => false, 'error' => "Аккаунт #{$accountId} не найден или неактивен"]));
    }

    $log = [];
    $result = $manager->addFriendsFromAccount(
        $account,
        $targetIds,
        $accounts, // все активные аккаунты — нужны, чтобы залогинить B и redeem'нуть quick-invite
        function (string $msg) use (&$log) {
            $log[] = $msg;
        }
    );

    // Обновить кэш
    updateFriendCache($cacheFile, $account['steamid64'], $targetIds, $result);

    echo json_encode([
        'ok'     => true,
        'login'  => $account['login'],
        'region' => $account['region'],
        'sent'   => count($result['sent']),
        'errors' => count($result['errors']),
        'error_details' => array_map(fn($e) => $e['error'] ?? '?', $result['errors']),
        'log'    => $log,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ============================================================
// CHECK_ONE — проверить друзей одного аккаунта
// ============================================================
if ($action === 'check_one') {
    $accountId   = (int)($_POST['account_id'] ?? 0);
    $allSteamIds = $_POST['all_steam_ids'] ?? [];

    if (!$accountId || empty($allSteamIds)) {
        die(json_encode(['ok' => false, 'error' => 'account_id и all_steam_ids[] обязательны']));
    }

    $accounts = $manager->getAccounts();
    $account  = null;
    foreach ($accounts as $a) {
        if ((int)$a['id'] === $accountId) { $account = $a; break; }
    }
    if (!$account) {
        die(json_encode(['ok' => false, 'error' => "Аккаунт #{$accountId} не найден"]));
    }

    try {
        $friends = $manager->checkFriendsForAccount($account, $allSteamIds);
    } catch (Throwable $e) {
        die(json_encode(['ok' => false, 'error' => $e->getMessage(), 'login' => $account['login']]));
    }

    // Сохранить в кэш
    $cache = is_file($cacheFile) ? json_decode(file_get_contents($cacheFile), true) : [];
    $cache[$account['steamid64']] = [
        'friends'    => $friends,
        'checked_at' => date('Y-m-d H:i:s'),
    ];
    file_put_contents($cacheFile, json_encode($cache, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX);

    echo json_encode([
        'ok'       => true,
        'login'    => $account['login'],
        'steamid'  => $account['steamid64'],
        'friends'  => $friends,
        'count'    => count($friends),
        'total'    => count($allSteamIds) - 1, // минус сам себя
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

die(json_encode(['ok' => false, 'error' => "Unknown action: {$action}"]));

// ============================================================

function updateFriendCache(string $cacheFile, string $steamid, array $targetIds, array $result): void
{
    $cache = is_file($cacheFile) ? json_decode(file_get_contents($cacheFile), true) : [];

    $existing = $cache[$steamid]['friends'] ?? [];
    foreach ($result['sent'] as $s) {
        $target = $s['target'] ?? '';
        if ($target && !in_array($target, $existing)) {
            $existing[] = $target;
        }
    }
    $cache[$steamid] = [
        'friends'    => array_values(array_unique($existing)),
        'checked_at' => date('Y-m-d H:i:s'),
    ];

    @file_put_contents($cacheFile, json_encode($cache, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX);
}
