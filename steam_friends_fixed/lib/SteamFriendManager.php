<?php
declare(strict_types=1);

/**
 * SteamFriendManager — добавление Steam-аккаунтов в друзья друг к другу.
 *
 * Метод: IPlayerService/AddFriend/v1/ с параметром key=access_token.
 * Для гарантии: обе стороны вызывают AddFriend друг на друга.
 * Когда A отправил заявку B, и B вызывает AddFriend на A — Steam автоматически
 * принимает встречную заявку → двусторонняя дружба.
 *
 * Логин: RSA → BeginAuth → PollAuth (protobuf, 1-в-1 как SteamStoreSession).
 */
class SteamFriendManager
{
    private const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                    . '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

    private string $logDir;
    private ?PDO $pdo;
    private bool $protobufLoaded = false;
    private bool $cryptoLoaded   = false;

    /** @var array<string, array> Кэш сессий: steamid64 → {steamid, token, proxy} */
    private array $sessionCache = [];

    public function __construct(string $logDir, ?PDO $pdo = null)
    {
        $this->logDir = $logDir;
        $this->pdo    = $pdo;
        if (!is_dir($logDir)) @mkdir($logDir, 0775, true);
    }

    // =========================================================================
    // Аккаунты из БД
    // =========================================================================

    public function getAccounts(): array
    {
        return $this->pdo->query(
            "SELECT id, region, title, login, steamid64, password_enc, is_active, 
                    checker_type, proxy_id
             FROM steam_checker_accounts 
             WHERE is_active = 1 AND steamid64 != '' AND steamid64 IS NOT NULL
             ORDER BY region, id"
        )->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getAllAccounts(): array
    {
        return $this->pdo->query(
            "SELECT id, region, title, login, steamid64, is_active, checker_type, proxy_id
             FROM steam_checker_accounts ORDER BY region, id"
        )->fetchAll(PDO::FETCH_ASSOC);
    }

    // =========================================================================
    // Добавление в друзья: IPlayerService/AddFriend/v1/
    // =========================================================================

    /**
     * Для аккаунта A и каждого target B:
     *   1. A → AddFriend(steamid=B)   — отправляет заявку A→B
     *   2. B → AddFriend(steamid=A)   — отправляет заявку B→A (авто-принимает встречную)
     *   → A и B теперь в друзьях
     *
     * @param array    $account        Аккаунт-источник
     * @param string[] $targetSteamIds Список steamid64 целей
     * @param array    $allAccounts    Все аккаунты (нужны для логина целей)
     */
    public function addFriendsFromAccount(
        array $account,
        array $targetSteamIds,
        array $allAccounts = [],
        ?callable $onProgress = null
    ): array {
        $results = ['sent' => [], 'errors' => []];
        $login   = $account['login'] ?? '?';
        $ownSid  = (string)($account['steamid64'] ?? '');

        // === Логин source ===
        try {
            $srcSess = $this->ensureSession($account);
        } catch (Throwable $e) {
            $msg = $this->shortError($e->getMessage());
            $results['errors'][] = ['target' => '*', 'error' => "login: {$msg}"];
            return $results;
        }
        if ($onProgress) $onProgress("✅ {$login}: залогинен (steamId={$srcSess['steamid']})");

        // === Lookup: steamid64 → данные аккаунта ===
        $accountBySid = [];
        foreach ($allAccounts as $a) {
            $sid = (string)($a['steamid64'] ?? '');
            if ($sid !== '') $accountBySid[$sid] = $a;
        }

        // === Проверяем кто уже в друзьях ===
        $friendSet = [];
        try {
            $friendSet = $this->fetchFriendSet($srcSess['token'], $srcSess['proxy']);
        } catch (Throwable $e) {
            $this->log("fetchFriendSet {$login}: " . $this->shortError($e->getMessage()));
        }

        foreach ($targetSteamIds as $targetSid) {
            $targetSid = (string)$targetSid;
            if ($targetSid === '' || $targetSid === $ownSid || $targetSid === $srcSess['steamid']) continue;

            // Уже друзья — пропускаем
            if (isset($friendSet[$targetSid])) {
                $results['sent'][] = ['target' => $targetSid, 'result' => 'already_friends'];
                if ($onProgress) $onProgress("  ✓ {$targetSid}: already_friends");
                continue;
            }

            // Нужны креды target-а
            if (!isset($accountBySid[$targetSid])) {
                $results['errors'][] = ['target' => $targetSid, 'error' => 'нет данных аккаунта-цели'];
                if ($onProgress) $onProgress("  ✕ {$targetSid}: нет данных аккаунта в allAccounts");
                continue;
            }

            try {
                // === Шаг 1: A → AddFriend(B) ===
                $res1 = $this->playerAddFriend($srcSess['token'], $targetSid, $srcSess['proxy']);
                $this->log("AddFriend {$login} -> {$targetSid}: {$res1}");
                if ($onProgress) $onProgress("  → {$login} → {$targetSid}: {$res1}");

                usleep(random_int(300_000, 600_000));

                // === Шаг 2: B → AddFriend(A) — авто-принимает встречную заявку ===
                $tgtSess  = $this->ensureSession($accountBySid[$targetSid]);
                $tgtLogin = $accountBySid[$targetSid]['login'] ?? '?';

                $res2 = $this->playerAddFriend($tgtSess['token'], $srcSess['steamid'], $tgtSess['proxy']);
                $this->log("AddFriend {$tgtLogin} -> {$srcSess['steamid']}: {$res2}");
                if ($onProgress) $onProgress("  ← {$tgtLogin} → {$srcSess['steamid']}: {$res2}");

                // Определяем итоговый статус
                $finalStatus = $this->combinedStatus($res1, $res2);
                $results['sent'][] = ['target' => $targetSid, 'result' => $finalStatus];
                if ($onProgress) $onProgress("  ✓ {$targetSid}: {$finalStatus}");

            } catch (Throwable $e) {
                $msg = $this->shortError($e->getMessage());
                $results['errors'][] = ['target' => $targetSid, 'error' => $msg];
                if ($onProgress) $onProgress("  ✕ {$targetSid}: {$msg}");
            }

            usleep(random_int(500_000, 1_200_000));
        }

        return $results;
    }

    /**
     * POST https://api.steampowered.com/IPlayerService/AddFriend/v1/
     * Параметры: key=access_token, steamid=target_steamid64
     *
     * @return string Статус: 'invite_sent', 'already_friends', 'accepted', ошибка и т.д.
     */
    private function playerAddFriend(string $accessToken, string $targetSteamId64, ?array $proxy): string
    {
        $url = 'https://api.steampowered.com/IPlayerService/AddFriend/v1/';

        $body = http_build_query([
            'key'     => $accessToken,
            'steamid' => $targetSteamId64,
        ]);

        $resp = $this->httpRequest('POST', $url, $body, $proxy, [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json, */*',
        ]);

        $this->log("IPlayerService/AddFriend {$targetSteamId64}: HTTP {$resp['code']} body="
                  . $this->safeLogBody($resp['body']));

        // HTTP 200 = успех
        if ($resp['code'] === 200) {
            $data = json_decode($resp['body'], true);
            $inner = $data['response'] ?? $data ?? [];

            // Пустой response {} = заявка отправлена или принята
            if (empty($inner) || $inner === []) {
                return 'ok';
            }

            // friend_relationship: 2=friends, 3=requestRecipient
            if (isset($inner['friend_relationship'])) {
                return match ((int)$inner['friend_relationship']) {
                    2 => 'already_friends',
                    3 => 'invite_sent',
                    default => 'ok (rel=' . $inner['friend_relationship'] . ')',
                };
            }
            if (!empty($inner['invite_sent'])) return 'invite_sent';

            return 'ok';
        }

        // Ошибки
        if ($resp['code'] === 401) return 'token_invalid (401)';

        // Protobuf или JSON ошибка
        $data = json_decode($resp['body'], true);
        if (is_array($data)) {
            $eresult = $data['response']['eresult'] ?? $data['eresult'] ?? null;
            if ($eresult !== null) {
                return match ((int)$eresult) {
                    1  => 'ok',
                    14 => 'already_friends',
                    24 => 'rate_limited',
                    25 => 'invite_already_sent',
                    40 => 'blocked',
                    84 => 'limit_exceeded',
                    default => "eresult={$eresult}",
                };
            }
        }

        throw new RuntimeException("HTTP {$resp['code']}: " . $this->safeLogBody($resp['body'], 150));
    }

    /** Определяет итоговый статус по двум направлениям. */
    private function combinedStatus(string $res1, string $res2): string
    {
        $friends = ['already_friends', 'ok'];
        if (in_array($res1, $friends, true) && in_array($res2, $friends, true)) {
            return 'friends';
        }
        if ($res1 === 'already_friends' || $res2 === 'already_friends') {
            return 'already_friends';
        }
        return "A:{$res1} B:{$res2}";
    }

    // =========================================================================
    // Проверка друзей
    // =========================================================================

    public function checkFriendsForAccount(array $account, array $allSteamIds): array
    {
        $sess   = $this->ensureSession($account);
        $ownSid = $account['steamid64'] ?? '';
        $allSet = array_flip($allSteamIds);
        $set    = $this->fetchFriendSet($sess['token'], $sess['proxy']);

        $matched = [];
        foreach ($set as $fid => $_) {
            if (isset($allSet[$fid]) && $fid !== $ownSid) {
                $matched[] = $fid;
            }
        }
        return $matched;
    }

    private function fetchFriendSet(string $accessToken, ?array $proxy): array
    {
        // Пробуем IPlayerService (key=), fallback на IFriendsListService (access_token=)
        $url = 'https://api.steampowered.com/IPlayerService/GetFriendList/v1/?'
             . http_build_query(['key' => $accessToken]);
        $resp = $this->httpRequest('GET', $url, null, $proxy, ['Accept: application/json']);

        if ($resp['code'] !== 200) {
            // Fallback
            $url = 'https://api.steampowered.com/IFriendsListService/GetFriendsList/v1/?'
                 . http_build_query(['access_token' => $accessToken]);
            $resp = $this->httpRequest('GET', $url, null, $proxy, ['Accept: application/json']);
        }

        $this->log("GetFriendList: HTTP {$resp['code']}");

        if ($resp['code'] !== 200) throw new RuntimeException("GetFriendList: HTTP {$resp['code']}");
        $data = json_decode($resp['body'], true);
        $friends = $data['response']['friendslist']['friends']
                ?? $data['response']['friends']
                ?? $data['friendslist']['friends']
                ?? [];
        $set = [];
        foreach ($friends as $f) {
            $sid = (string)($f['steamid'] ?? '');
            if ($sid !== '') $set[$sid] = true;
        }
        return $set;
    }

    // =========================================================================
    // Сессия: login → access_token (с кэшированием)
    // =========================================================================

    private function ensureSession(array $account): array
    {
        $sid = (string)($account['steamid64'] ?? '');
        if ($sid !== '' && isset($this->sessionCache[$sid])) {
            return $this->sessionCache[$sid];
        }

        $this->loadDependencies();
        if (!$this->protobufLoaded) throw new RuntimeException('SteamProtobufCodec не найден');
        if (!$this->cryptoLoaded)   throw new RuntimeException('SteamCrypto не найден');

        $password = SteamCrypto::decrypt($account['password_enc'] ?? '');
        if ($password === '') throw new RuntimeException('Пароль пуст');

        $login = trim($account['login'] ?? '');
        if ($login === '') throw new RuntimeException('Логин пуст');

        $proxy = $this->loadProxyForAccount($account);

        $this->log("LOGIN start login={$login}");

        // 1. RSA key
        [$pubKey, $ts] = $this->getPasswordRSAPublicKey($login, $proxy);

        // 2. Encrypt password
        $encPwd = $this->rsaEncryptPassword($password, $pubKey);

        // 3. BeginAuth
        [$clientId, $requestId, $steamId, $guards] = $this->beginAuthSession($login, $encPwd, $ts, $proxy);
        $this->log("LOGIN step3 steamId={$steamId} guards=" . implode(',', $guards));

        if ($guards && !in_array(0, $guards, true) && !in_array(1, $guards, true)) {
            throw new RuntimeException('2FA required (guard=' . implode(',', $guards) . ')');
        }

        // 4. Poll → tokens
        $tokens = $this->pollAuthSession($clientId, $requestId, $proxy);
        $this->log("LOGIN ok {$login} access_token len=" . strlen($tokens['access_token']));

        $entry = [
            'steamid' => $steamId,
            'token'   => $tokens['access_token'],
            'proxy'   => $proxy,
        ];

        $this->sessionCache[$steamId] = $entry;
        if ($sid !== '' && $sid !== $steamId) {
            $this->sessionCache[$sid] = $entry;
        }

        return $entry;
    }

    // =========================================================================
    // Steam Auth (protobuf, 1-в-1 как SteamStoreSession)
    // =========================================================================

    private function getPasswordRSAPublicKey(string $login, ?array $proxy): array
    {
        $proto = SteamProtobufCodec::encodeString(1, $login);
        $url = 'https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/'
             . '?origin=' . urlencode('https://store.steampowered.com')
             . '&input_protobuf_encoded=' . urlencode(base64_encode($proto));

        $resp = $this->httpRequest('GET', $url, null, $proxy);
        if ($resp['code'] !== 200) throw new RuntimeException("RSA: HTTP {$resp['code']}");

        $d = SteamProtobufCodec::decode($resp['body']);
        $mod = is_string($d[1] ?? null) ? $d[1] : null;
        $exp = is_string($d[2] ?? null) ? $d[2] : null;
        $ts  = isset($d[3]) ? (string)(is_string($d[3]) ? SteamProtobufCodec::decodeVarintFromBytes($d[3]) : $d[3]) : null;
        if (!$mod || !$exp || !$ts) throw new RuntimeException('RSA: incomplete');

        return [$this->hexRsaToPem($mod, $exp), $ts];
    }

    private function rsaEncryptPassword(string $password, string $pem): string
    {
        if (!openssl_public_encrypt($password, $enc, $pem, OPENSSL_PKCS1_PADDING)) {
            throw new RuntimeException('RSA encrypt: ' . openssl_error_string());
        }
        return base64_encode($enc);
    }

    private function beginAuthSession(string $login, string $encPwd, string $ts, ?array $proxy): array
    {
        $dd = SteamProtobufCodec::encodeString(1, self::UA)
            . SteamProtobufCodec::encodeVarint(2, 2);

        $proto = SteamProtobufCodec::encodeString(1, self::UA)
               . SteamProtobufCodec::encodeString(2, $login)
               . SteamProtobufCodec::encodeString(3, $encPwd)
               . SteamProtobufCodec::encodeVarint(4, (int)$ts)
               . SteamProtobufCodec::encodeVarint(5, 1)
               . SteamProtobufCodec::encodeVarint(6, 2)
               . SteamProtobufCodec::encodeVarint(7, 1)
               . SteamProtobufCodec::encodeString(8, 'Store')
               . SteamProtobufCodec::encodeString(9, $dd)
               . SteamProtobufCodec::encodeVarint(11, 8)
               . SteamProtobufCodec::encodeVarint(12, 2);

        $resp = $this->postProtobuf(
            'https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/',
            $proto, $proxy
        );
        $er = $resp['headers']['x-eresult'] ?? '';
        if ($resp['code'] !== 200 || ($er !== '' && $er !== '1')) {
            throw new RuntimeException("BeginAuth: HTTP {$resp['code']} eresult={$er}");
        }

        $d = SteamProtobufCodec::decode($resp['body']);
        $clientId  = isset($d[1]) ? (int)$d[1] : 0;
        $requestId = is_string($d[2] ?? null) ? $d[2] : '';
        $steamId   = isset($d[5]) ? (string)$d[5] : '';

        $guards = [];
        $raw = $d[4] ?? null;
        if (is_string($raw)) {
            $sub = SteamProtobufCodec::decode($raw);
            if (isset($sub[1])) $guards[] = (int)$sub[1];
        } elseif (is_array($raw)) {
            foreach ($raw as $r) {
                if (!is_string($r)) continue;
                $sub = SteamProtobufCodec::decode($r);
                if (isset($sub[1])) $guards[] = (int)$sub[1];
            }
        }

        if (!$clientId || !$requestId) throw new RuntimeException("BeginAuth: no client_id");
        return [$clientId, $requestId, $steamId, $guards];
    }

    private function pollAuthSession(int $clientId, string $requestId, ?array $proxy): array
    {
        $proto = SteamProtobufCodec::encodeVarint(1, $clientId)
               . SteamProtobufCodec::encodeString(2, $requestId);

        for ($i = 0; $i < 20; $i++) {
            $resp = $this->postProtobuf(
                'https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/',
                $proto, $proxy
            );
            if ($resp['code'] !== 200) throw new RuntimeException("Poll: HTTP {$resp['code']}");

            $d = SteamProtobufCodec::decode($resp['body']);
            $refresh = is_string($d[3] ?? null) ? $d[3] : '';
            $access  = is_string($d[4] ?? null) ? $d[4] : '';

            if ($refresh !== '') {
                if ($access === '') {
                    $access = $this->generateAccessToken($refresh, $proxy) ?? '';
                }
                if ($access === '') {
                    throw new RuntimeException('Poll: got refresh but no access_token');
                }
                return ['access_token' => $access, 'refresh_token' => $refresh];
            }
            usleep(500_000);
        }
        throw new RuntimeException('Poll: timeout');
    }

    private function generateAccessToken(string $refreshToken, ?array $proxy): ?string
    {
        $proto = SteamProtobufCodec::encodeString(1, $refreshToken);
        $resp = $this->postProtobuf(
            'https://api.steampowered.com/IAuthenticationService/GenerateAccessTokenForApp/v1/',
            $proto, $proxy
        );
        if ($resp['code'] !== 200) return null;
        $d = SteamProtobufCodec::decode($resp['body']);
        return is_string($d[1] ?? null) ? $d[1] : null;
    }

    // =========================================================================
    // HTTP helpers
    // =========================================================================

    private function postProtobuf(string $url, string $proto, ?array $proxy): array
    {
        $boundary = '----PHP' . bin2hex(random_bytes(8));
        $body = "--{$boundary}\r\nContent-Disposition: form-data; name=\"input_protobuf_encoded\"\r\n\r\n"
              . base64_encode($proto) . "\r\n--{$boundary}--\r\n";

        return $this->httpRequest('POST', $url, $body, $proxy, [
            'Accept: */*',
            'Content-Type: multipart/form-data; boundary=' . $boundary,
            'Origin: https://store.steampowered.com',
            'Referer: https://store.steampowered.com/',
        ]);
    }

    private function httpRequest(string $method, string $url, ?string $body, ?array $proxy, array $headers = []): array
    {
        $ch = curl_init();
        $respHeaders = [];
        $opts = [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_ENCODING       => '',
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_USERAGENT      => self::UA,
            CURLOPT_HTTPHEADER     => array_merge(['Accept-Language: ru,en;q=0.9'], $headers),
            CURLOPT_HEADERFUNCTION => function ($ch, string $h) use (&$respHeaders) {
                if (($p = strpos($h, ':')) !== false) {
                    $k = strtolower(trim(substr($h, 0, $p)));
                    $v = trim(substr($h, $p + 1));
                    if ($k === 'set-cookie') {
                        $respHeaders[$k] = $respHeaders[$k] ?? [];
                        $respHeaders[$k][] = $v;
                    } else {
                        $respHeaders[$k] = $v;
                    }
                }
                return strlen($h);
            },
        ];

        if ($method === 'POST') {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $body ?? '';
        }

        if ($proxy) {
            $scheme = strtolower((string)($proxy['scheme'] ?? 'http'));
            $opts[CURLOPT_PROXY] = $proxy['host'] . ':' . (int)$proxy['port'];
            $opts[CURLOPT_PROXYTYPE] = match ($scheme) {
                'socks5' => CURLPROXY_SOCKS5_HOSTNAME,
                'socks4' => CURLPROXY_SOCKS4,
                default  => CURLPROXY_HTTP,
            };
            if (!empty($proxy['username'])) {
                $opts[CURLOPT_PROXYUSERPWD] = $proxy['username'] . ':' . (string)($proxy['password'] ?? '');
            }
        }

        curl_setopt_array($ch, $opts);
        $respBody = curl_exec($ch);
        $err      = curl_error($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($respBody === false) throw new RuntimeException("cURL: {$err}");

        return ['code' => $httpCode, 'body' => (string)$respBody, 'headers' => $respHeaders];
    }

    // =========================================================================
    // RSA helpers
    // =========================================================================

    private function hexRsaToPem(string $modHex, string $expHex): string
    {
        $mod = hex2bin($modHex); $exp = hex2bin($expHex);
        if (!$mod || !$exp) throw new RuntimeException('RSA hex decode fail');
        if (ord($mod[0]) & 0x80) $mod = "\x00" . $mod;
        if (ord($exp[0]) & 0x80) $exp = "\x00" . $exp;

        $encInt = fn(string $b) => "\x02" . self::asn1Len(strlen($b)) . $b;
        $seq = $encInt($mod) . $encInt($exp);
        $rsaSeq = "\x30" . self::asn1Len(strlen($seq)) . $seq;
        $algOid = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $algSeq = "\x30" . self::asn1Len(strlen($algOid)) . $algOid;
        $bit    = "\x03" . self::asn1Len(strlen($rsaSeq) + 1) . "\x00" . $rsaSeq;
        $spki   = "\x30" . self::asn1Len(strlen($algSeq) + strlen($bit)) . $algSeq . $bit;

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function asn1Len(int $len): string
    {
        if ($len < 0x80) return chr($len);
        $hex = dechex($len); if (strlen($hex) % 2) $hex = '0' . $hex;
        $bin = hex2bin($hex);
        return chr(0x80 | strlen($bin)) . $bin;
    }

    // =========================================================================
    // Dependencies
    // =========================================================================

    private function loadDependencies(): void
    {
        $checkerRoot = dirname(__DIR__);
        $projectRoot = dirname($checkerRoot);

        $paths = [
            'proto' => [
                $projectRoot . '/steamtopup/steam_topup/SteamProtobufCodec.php',
                $projectRoot . '/test/steam_gift_region_checker/steam_topup/SteamProtobufCodec.php',
            ],
            'crypto' => [
                $projectRoot . '/steamtopup/steam_topup/SteamAccountsRepo.php',
                $projectRoot . '/test/steam_gift_region_checker/steam_topup/SteamAccountsRepo.php',
            ],
        ];

        if (!class_exists('SteamProtobufCodec', false)) {
            foreach ($paths['proto'] as $p) { if (is_file($p)) { require_once $p; break; } }
        }
        $this->protobufLoaded = class_exists('SteamProtobufCodec', false);

        if (!class_exists('SteamCrypto', false)) {
            foreach ($paths['crypto'] as $p) { if (is_file($p)) { require_once $p; break; } }
        }
        $this->cryptoLoaded = class_exists('SteamCrypto', false);
    }

    private function loadProxyForAccount(array $account): ?array
    {
        if (empty($account['proxy_id']) || !$this->pdo) return null;
        try {
            $stmt = $this->pdo->prepare('SELECT * FROM steam_proxies WHERE id = ? AND active = 1');
            $stmt->execute([(int)$account['proxy_id']]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable) { return null; }
        if (!$row) return null;
        return ['scheme' => $row['scheme'] ?? 'http', 'host' => $row['host'],
                'port' => (int)$row['port'], 'username' => $row['username'] ?? null,
                'password' => $row['password'] ?? null];
    }

    private function safeLogBody(string $body, int $max = 300): string
    {
        if ($body === '') return '(empty)';
        if (json_decode($body, true) !== null) return mb_substr($body, 0, $max);
        if (preg_match('/[^\x20-\x7E\r\n\t]/', $body)) return '(binary ' . strlen($body) . 'b) hex=' . bin2hex(substr($body, 0, 40));
        return mb_substr($body, 0, $max);
    }

    private function shortError(string $msg): string
    {
        $msg = trim(preg_replace('/\s+/', ' ', $msg));
        if (preg_match('~^(.*?)<\s*/?\s*html\b~is', $msg, $m)) $msg = trim($m[1]);
        return mb_strlen($msg) > 160 ? mb_substr($msg, 0, 160) . "\xe2\x80\xa6" : ($msg ?: 'unknown');
    }

    private function log(string $msg): void
    {
        @file_put_contents(
            $this->logDir . '/friends_' . date('Y-m-d') . '.log',
            date('Y-m-d H:i:s') . " [FriendMgr] {$msg}\n",
            FILE_APPEND
        );
    }
}
