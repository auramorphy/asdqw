<?php
declare(strict_types=1);

/**
 * SteamFriendManager — добавление Steam-аккаунтов чекеров в друзья друг к другу.
 *
 * Используется официальный поток quick-invite-токенов (s.team/p/...):
 *   1. Аккаунт логинится, получает access_token.
 *   2. CreateFriendInviteToken (IUserAccountService) → личный invite_token,
 *      хранится в logs/invite_tokens.json (только для внутренней логики,
 *      нигде не выводится в UI и не пишется в человеческий лог).
 *   3. Остальные аккаунты при логине вызывают RedeemFriendInviteToken
 *      (IUserAccountService) с этим токеном — после чего пара становится
 *      взаимными друзьями.
 *
 * Старый IFriendsListService/AddFriend/v1/ Steam удалил (HTTP 404 Not Found).
 *
 * Зависимости:
 *   - SteamProtobufCodec (protobuf encode/decode)
 *   - SteamCrypto         (расшифровка пароля из БД)
 */
class SteamFriendManager
{
    private const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                    . '(KHTML, like Gecko) Chrome/144.0.0.0 YaBrowser/26.3.0.0 Safari/537.36';

    private string $logDir;
    private ?PDO $pdo;
    private bool $protobufLoaded = false;
    private bool $cryptoLoaded   = false;

    public function __construct(string $logDir, ?PDO $pdo = null)
    {
        $this->logDir = $logDir;
        $this->pdo    = $pdo;
        if (!is_dir($logDir)) @mkdir($logDir, 0775, true);
    }

    // =========================================================================
    // Аккаунты из БД
    // =========================================================================

    /** Активные аккаунты с steamid64 (готовые к работе). */
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

    /** Все аккаунты (для таблицы). */
    public function getAllAccounts(): array
    {
        return $this->pdo->query(
            "SELECT id, region, title, login, steamid64, is_active, checker_type, proxy_id
             FROM steam_checker_accounts ORDER BY region, id"
        )->fetchAll(PDO::FETCH_ASSOC);
    }

    // =========================================================================
    // Авторизация → access_token (через Steam Auth protobuf API)
    // =========================================================================

    /**
     * Полный цикл авторизации: RSA → BeginAuth → PollAuth → access_token.
     *
     * В отличие от SteamStoreSession, здесь НЕ нужны cookies/sessionid —
     * нужен только access_token для вызова IFriendsListService.
     *
     * @return array{token: string, steamId: string}
     */
    private function loginAndGetToken(array $account): array
    {
        $this->loadDependencies();
        if (!$this->protobufLoaded) throw new RuntimeException('SteamProtobufCodec не найден');
        if (!$this->cryptoLoaded)   throw new RuntimeException('SteamCrypto не найден');

        $password = SteamCrypto::decrypt($account['password_enc'] ?? '');
        if ($password === '') throw new RuntimeException('Пароль пуст');

        $login = trim($account['login'] ?? '');
        if ($login === '') throw new RuntimeException('Логин пуст');

        // Загружаем прокси если есть
        $proxy = null;
        if (!empty($account['proxy_id']) && $this->pdo) {
            $proxy = $this->loadProxy((int)$account['proxy_id']);
        }

        $this->log("LOGIN start login={$login}");

        // Step 1. RSA-ключ для шифрования пароля
        [$publicKey, $timestamp] = $this->getPasswordRSAPublicKey($login, $proxy);
        $this->log("LOGIN step1 RSA key ok, ts={$timestamp}");

        // Step 2. Шифруем пароль RSA/PKCS1
        $encryptedPassword = $this->rsaEncryptPassword($password, $publicKey);

        // Step 3. BeginAuthSessionViaCredentials
        [$clientId, $requestId, $steamId, $allowedConf] =
            $this->beginAuthSession($login, $encryptedPassword, $timestamp, $proxy);
        $this->log("LOGIN step3 client_id={$clientId} steam_id={$steamId} guards=" . implode(',', $allowedConf));

        if ($allowedConf && !in_array(0, $allowedConf, true) && !in_array(1, $allowedConf, true)) {
            throw new RuntimeException(
                'Steam требует 2FA (guard=' . implode(',', $allowedConf) . ')'
            );
        }

        // Step 4. PollAuthSessionStatus → access_token
        $accessToken = $this->pollAuthSession($clientId, $requestId, $proxy);
        $this->log("LOGIN step4 access_token ok, len=" . strlen($accessToken));

        if (!$accessToken) {
            throw new RuntimeException('Не получен access_token из PollAuthSession');
        }

        return ['token' => $accessToken, 'steamId' => $steamId];
    }

    // =========================================================================
    // Steam Auth protobuf — шаги авторизации
    // =========================================================================

    /**
     * Step 1: получить RSA-ключ для шифрования пароля.
     * @return array{0: string, 1: string} [PEM public key, timestamp]
     */
    private function getPasswordRSAPublicKey(string $accountName, ?array $proxy): array
    {
        $proto = SteamProtobufCodec::encodeString(1, $accountName);
        $encoded = base64_encode($proto);

        $url = 'https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/'
             . '?origin=' . urlencode('https://store.steampowered.com')
             . '&input_protobuf_encoded=' . urlencode($encoded);

        $resp = $this->httpRequest('GET', $url, null, $proxy);
        if ($resp['code'] !== 200) {
            throw new RuntimeException("GetPasswordRSAPublicKey: HTTP {$resp['code']}");
        }

        $decoded = SteamProtobufCodec::decode($resp['body']);
        $mod = isset($decoded[1]) && is_string($decoded[1]) ? $decoded[1] : null;
        $exp = isset($decoded[2]) && is_string($decoded[2]) ? $decoded[2] : null;
        $ts  = isset($decoded[3])
            ? (string)(is_string($decoded[3]) ? SteamProtobufCodec::decodeVarintFromBytes($decoded[3]) : $decoded[3])
            : null;
        if (!$mod || !$exp || !$ts) {
            throw new RuntimeException('GetPasswordRSAPublicKey: неполный ответ');
        }

        $publicKeyPem = $this->hexRsaToPem($mod, $exp);
        return [$publicKeyPem, $ts];
    }

    /** Step 2: шифрование пароля RSA/PKCS1. */
    private function rsaEncryptPassword(string $password, string $publicKeyPem): string
    {
        $ok = openssl_public_encrypt($password, $encrypted, $publicKeyPem, OPENSSL_PKCS1_PADDING);
        if (!$ok) throw new RuntimeException('RSA encrypt failed: ' . openssl_error_string());
        return base64_encode($encrypted);
    }

    /**
     * Step 3: BeginAuthSessionViaCredentials.
     * @return array{0:int, 1:string, 2:string, 3:int[]}
     *   [clientId, requestId(bytes), steamId, allowedConfirmations]
     */
    private function beginAuthSession(string $login, string $encPwd, string $ts, ?array $proxy): array
    {
        // CAuthentication_DeviceDetails
        $deviceDetails  = SteamProtobufCodec::encodeString(1, self::UA)
                       . SteamProtobufCodec::encodeVarint(2, 2); // WebBrowser

        $proto  = SteamProtobufCodec::encodeString(1, self::UA);        // device_friendly_name
        $proto .= SteamProtobufCodec::encodeString(2, $login);          // account_name
        $proto .= SteamProtobufCodec::encodeString(3, $encPwd);         // encrypted_password
        $proto .= SteamProtobufCodec::encodeVarint(4, (int)$ts);        // encryption_timestamp
        $proto .= SteamProtobufCodec::encodeVarint(5, 1);               // remember_login
        $proto .= SteamProtobufCodec::encodeVarint(6, 2);               // platform_type = WebBrowser
        $proto .= SteamProtobufCodec::encodeVarint(7, 1);               // persistence = Persistent
        $proto .= SteamProtobufCodec::encodeString(8, 'Store');         // website_id
        $proto .= SteamProtobufCodec::encodeString(9, $deviceDetails);  // device_details
        $proto .= SteamProtobufCodec::encodeVarint(11, 8);              // language = russian
        $proto .= SteamProtobufCodec::encodeVarint(12, 2);              // qos_level

        $resp = $this->postProtobuf(
            'https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/',
            $proto, $proxy
        );

        $er = $resp['headers']['x-eresult'] ?? '';
        if ($resp['code'] !== 200 || ($er !== '' && $er !== '1')) {
            throw new RuntimeException('BeginAuth: HTTP ' . $resp['code'] . ' eresult=' . $er);
        }
        if (strlen($resp['body']) === 0) {
            throw new RuntimeException('BeginAuth: пустой ответ (eresult=' . $er . ')');
        }

        $decoded = SteamProtobufCodec::decode($resp['body']);
        $clientId  = isset($decoded[1]) ? (int)$decoded[1] : 0;
        $requestId = isset($decoded[2]) && is_string($decoded[2]) ? $decoded[2] : '';
        $steamId   = isset($decoded[5]) ? (string)$decoded[5] : '';

        // Разбираем allowedConfirmations (повторяющееся поле 4)
        $allowed = [];
        $raw = $decoded[4] ?? null;
        if (is_string($raw)) {
            $sub = SteamProtobufCodec::decode($raw);
            if (isset($sub[1])) $allowed[] = (int)$sub[1];
        } elseif (is_array($raw)) {
            foreach ($raw as $r) {
                if (!is_string($r)) continue;
                $sub = SteamProtobufCodec::decode($r);
                if (isset($sub[1])) $allowed[] = (int)$sub[1];
            }
        }

        if ($clientId === 0 || $requestId === '') {
            throw new RuntimeException('BeginAuth: нет client_id/request_id (eresult=' . $er . ')');
        }

        return [$clientId, $requestId, $steamId, $allowed];
    }

    /**
     * Step 4: PollAuthSessionStatus — получаем access_token.
     *
     * Ответ PollAuthSessionStatus содержит:
     *   field 3 = refresh_token (нужен для cookies/finalizeLogin)
     *   field 4 = access_token  (нужен для Steam Web API)
     *
     * SteamStoreSession берёт refresh_token (field 3) для обмена на cookies.
     * Нам нужен access_token (field 4) для IFriendsListService.
     */
    private function pollAuthSession(int $clientId, string $requestId, ?array $proxy): string
    {
        $proto  = SteamProtobufCodec::encodeVarint(1, $clientId);
        $proto .= SteamProtobufCodec::encodeString(2, $requestId);

        $maxAttempts = 20;
        $delayMs = 500;

        for ($i = 0; $i < $maxAttempts; $i++) {
            $resp = $this->postProtobuf(
                'https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/',
                $proto, $proxy
            );
            if ($resp['code'] !== 200) {
                $er = $resp['headers']['x-eresult'] ?? '';
                throw new RuntimeException("PollAuth: HTTP {$resp['code']} eresult={$er}");
            }

            $decoded = SteamProtobufCodec::decode($resp['body']);
            // field 3 = refresh_token, field 4 = access_token
            $refreshToken = isset($decoded[3]) && is_string($decoded[3]) ? $decoded[3] : '';
            $accessToken  = isset($decoded[4]) && is_string($decoded[4]) ? $decoded[4] : '';

            if ($accessToken !== '') {
                $this->log("PollAuth: got access_token len=" . strlen($accessToken)
                         . " refresh_token len=" . strlen($refreshToken));
                return $accessToken;
            }

            // Если refresh есть, а access нет — генерируем access через GenerateAccessTokenForApp
            if ($refreshToken !== '') {
                $this->log("PollAuth: got refresh_token but no access_token, trying GenerateAccessTokenForApp");
                $generated = $this->generateAccessTokenFromRefresh($refreshToken, $proxy);
                if ($generated) return $generated;
                // Если не получилось — используем refresh как fallback (маловероятно, что сработает)
                $this->log("PollAuth: GenerateAccessTokenForApp failed, using refresh_token as fallback");
                return $refreshToken;
            }

            usleep($delayMs * 1000);
        }

        throw new RuntimeException('PollAuth: за ' . ($maxAttempts * $delayMs / 1000) . 'с не получен token');
    }

    /**
     * Fallback: обменять refresh_token на access_token через GenerateAccessTokenForApp.
     */
    private function generateAccessTokenFromRefresh(string $refreshToken, ?array $proxy): ?string
    {
        $proto = SteamProtobufCodec::encodeString(1, $refreshToken);
        // field 2 = steamid (не обязательный для GenerateAccessTokenForApp)

        $resp = $this->postProtobuf(
            'https://api.steampowered.com/IAuthenticationService/GenerateAccessTokenForApp/v1/',
            $proto, $proxy
        );

        if ($resp['code'] !== 200) {
            $this->log("GenerateAccessTokenForApp: HTTP {$resp['code']}");
            return null;
        }

        $decoded = SteamProtobufCodec::decode($resp['body']);
        // field 1 = access_token
        $token = isset($decoded[1]) && is_string($decoded[1]) ? $decoded[1] : '';
        if ($token !== '') {
            $this->log("GenerateAccessTokenForApp: ok, len=" . strlen($token));
            return $token;
        }

        $this->log("GenerateAccessTokenForApp: нет access_token в ответе");
        return null;
    }

    // =========================================================================
    // Добавление в друзья через quick-invite-токены (IUserAccountService)
    // =========================================================================

    /**
     * Залогиниться, гарантировать наличие собственного quick-invite-токена,
     * погасить токены остальных аккаунтов — это и есть «добавить в друзья».
     *
     * После одного полного прохода по всем аккаунтам все пары становятся
     * взаимными друзьями (Steam friend-relationship симметричен).
     *
     * @param array $account Строка из steam_checker_accounts
     * @param string[] $targetSteamIds Список steamid64 всех аккаунтов
     * @param callable|null $onProgress function(string $message)
     * @return array ['sent' => [...], 'errors' => [...]]
     */
    public function addFriendsFromAccount(array $account, array $targetSteamIds, ?callable $onProgress = null): array
    {
        $results = ['sent' => [], 'errors' => []];
        $login   = $account['login'] ?? '?';
        $ownSid  = $account['steamid64'] ?? '';

        try {
            $auth = $this->loginAndGetToken($account);
        } catch (Throwable $e) {
            $msg = $this->shortError($e->getMessage());
            $results['errors'][] = ['target' => '*', 'error' => "login_failed: {$msg}"];
            $this->log("addFriends {$login} steamId={$ownSid}: login_failed: {$msg}");
            return $results;
        }

        $token   = $auth['token'];
        $proxy   = $this->loadProxyForAccount($account);
        $loginSid = $auth['steamId'] ?: $ownSid;

        // 1) гарантируем собственный invite_token (не логируем сам токен)
        try {
            $this->ensureOwnInviteToken($loginSid, $token, $proxy);
        } catch (Throwable $e) {
            $msg = $this->shortError($e->getMessage());
            $results['errors'][] = ['target' => '*', 'error' => "create_invite_failed: {$msg}"];
            $this->log("addFriends {$login} steamId={$loginSid}: create_invite_failed: {$msg}");
            return $results;
        }

        if ($onProgress) $onProgress("✅ {$login}: залогинен (steamId={$loginSid})");

        // 2) погашаем токены остальных аккаунтов
        $tokens = $this->loadInviteTokens();
        foreach ($targetSteamIds as $targetSid) {
            $targetSid = (string)$targetSid;
            if ($targetSid === '' || $targetSid === $loginSid || $targetSid === $ownSid) continue;

            $targetInvite = $tokens[$targetSid]['invite_token'] ?? null;
            if (!$targetInvite) {
                $results['sent'][] = ['target' => $targetSid, 'result' => 'no_invite_token'];
                if ($onProgress) $onProgress("  · {$targetSid}: no_invite_token (будет добавлен на следующем проходе)");
                continue;
            }

            try {
                $status = $this->apiRedeemInvite($token, $targetSid, $targetInvite, $proxy);
                if ($status === 'invite_expired' || $status === 'invalid_invite') {
                    // Токен у цели больше не годен — выкидываем из кэша,
                    // на следующем запуске цель создаст новый.
                    $this->forgetInviteToken($targetSid);
                }
                if ($status === 'failed' || str_starts_with($status, 'eresult=')) {
                    $results['errors'][] = ['target' => $targetSid, 'error' => $status];
                    $this->log("addFriends {$login} → {$targetSid}: {$status}");
                    if ($onProgress) $onProgress("  ✕ {$targetSid}: {$status}");
                } else {
                    $results['sent'][] = ['target' => $targetSid, 'result' => $status];
                    $this->log("addFriends {$login} → {$targetSid}: {$status}");
                    if ($onProgress) $onProgress("  ✓ {$targetSid}: {$status}");
                }
            } catch (Throwable $e) {
                $msg = $this->shortError($e->getMessage());
                $results['errors'][] = ['target' => $targetSid, 'error' => $msg];
                $this->log("addFriends {$login} → {$targetSid}: failed: {$msg}");
                if ($onProgress) $onProgress("  ✕ {$targetSid}: {$msg}");
            }

            usleep(random_int(400_000, 1_200_000));
        }

        return $results;
    }

    /**
     * Создать (или переиспользовать существующий) собственный quick-invite-токен
     * для указанного steamid. Возвращает токен. Никуда не логируется и не выводится.
     */
    private function ensureOwnInviteToken(string $ownSteamid, string $accessToken, ?array $proxy): string
    {
        $tokens = $this->loadInviteTokens();
        $cached = $tokens[$ownSteamid]['invite_token'] ?? null;
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $created = $this->apiCreateInviteToken($accessToken, $proxy);
        $invite  = (string)($created['invite_token'] ?? '');
        if ($invite === '') {
            throw new RuntimeException('CreateFriendInviteToken: пустой invite_token в ответе');
        }

        $this->saveInviteToken($ownSteamid, $invite, [
            'time_created' => $created['time_created'] ?? time(),
            'invite_limit' => $created['invite_limit'] ?? null,
            'valid'        => $created['valid'] ?? true,
        ]);
        return $invite;
    }

    /**
     * IUserAccountService/CreateFriendInviteToken/v1/
     *
     * @return array{invite_token:string,invite_limit:?int,invite_duration:?int,time_created:?int,valid:?bool}
     */
    private function apiCreateInviteToken(string $accessToken, ?array $proxy): array
    {
        // CUserAccount_CreateFriendInviteToken_Request:
        //   uint32 invite_limit = 1; uint32 invite_duration = 2; string invite_note = 3;
        // Все поля optional → отправляем пустое тело, Steam ставит дефолты.
        $proto = '';

        $url = 'https://api.steampowered.com/IUserAccountService/CreateFriendInviteToken/v1/?'
             . http_build_query(['access_token' => $accessToken]);

        $resp = $this->postProtobuf($url, $proto, $proxy);

        if ($resp['code'] !== 200) {
            $eresult = $resp['headers']['x-eresult'] ?? '';
            throw new RuntimeException("CreateFriendInviteToken: HTTP {$resp['code']}"
                . ($eresult !== '' ? " eresult={$eresult}" : ''));
        }

        $decoded = SteamProtobufCodec::decode($resp['body']);
        return [
            'invite_token'    => isset($decoded[1]) && is_string($decoded[1]) ? $decoded[1] : '',
            'invite_limit'    => isset($decoded[2]) ? (int)$decoded[2] : null,
            'invite_duration' => isset($decoded[3]) ? (int)$decoded[3] : null,
            'time_created'    => isset($decoded[4]) ? (int)$decoded[4] : null,
            'valid'           => isset($decoded[5]) ? (bool)$decoded[5] : null,
        ];
    }

    /**
     * IUserAccountService/RedeemFriendInviteToken/v1/
     *
     * @return string один из: 'invite_redeemed' | 'already_friends' | 'invite_expired'
     *                | 'invalid_invite' | 'rate_limited' | 'failed' | "eresult=N"
     */
    private function apiRedeemInvite(string $accessToken, string $ownerSteamid, string $inviteToken, ?array $proxy): string
    {
        // CUserAccount_RedeemFriendInviteToken_Request:
        //   fixed64 steamid = 1; string invite_token = 2;
        $proto  = self::encodeFixed64(1, $ownerSteamid);
        $proto .= SteamProtobufCodec::encodeString(2, $inviteToken);

        $url = 'https://api.steampowered.com/IUserAccountService/RedeemFriendInviteToken/v1/?'
             . http_build_query(['access_token' => $accessToken]);

        $resp    = $this->postProtobuf($url, $proto, $proxy);
        $eresult = $resp['headers']['x-eresult'] ?? '';

        if ($resp['code'] === 200 && ($eresult === '' || $eresult === '1')) {
            return 'invite_redeemed';
        }

        // Распознаваемые eresult из практики Steam Web API
        $er = (int)$eresult;
        return match ($er) {
            1   => 'invite_redeemed',
            2   => 'failed',                  // Generic Fail
            10  => 'invalid_invite',          // BadResponse / token не существует
            11  => 'invalid_invite',          // InvalidParam (часто = плохой токен)
            13  => 'invalid_invite',          // InvalidPassword (для invite — невалиден)
            15  => 'access_denied',
            24  => 'rate_limited',
            25  => 'rate_limited',            // LimitExceeded
            33  => 'already_friends',         // DuplicateRequest — уже друзья / уже погашен
            41  => 'invite_expired',
            50  => 'already_friends',
            84  => 'rate_limited',
            default => $eresult !== '' ? "eresult={$eresult}" : "failed",
        };
    }

    /**
     * Внутренняя ссылка вида https://s.team/p/<invite_token>.
     * Используется ТОЛЬКО логикой; в UI/логи не попадает.
     */
    public function getQuickInviteLink(array $account): ?string
    {
        $sid = (string)($account['steamid64'] ?? '');
        if ($sid === '') return null;
        $auth   = $this->loginAndGetToken($account);
        $proxy  = $this->loadProxyForAccount($account);
        $token  = $this->ensureOwnInviteToken($auth['steamId'] ?: $sid, $auth['token'], $proxy);
        return 'https://s.team/p/' . $token;
    }

    // =========================================================================
    // Проверка списка друзей
    // =========================================================================

    /**
     * Залогиниться и получить список друзей из чекер-аккаунтов.
     * @return string[] steamid64 тех из allSteamIds, кто в друзьях
     */
    public function checkFriendsForAccount(array $account, array $allSteamIds): array
    {
        $auth = $this->loginAndGetToken($account);
        $ownSid = $account['steamid64'] ?? '';

        $url = 'https://api.steampowered.com/IFriendsListService/GetFriendsList/v1/?'
             . http_build_query(['access_token' => $auth['token']]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_USERAGENT      => self::UA,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $this->log("GetFriendsList {$account['login']}: HTTP {$code}");

        if ($code !== 200 || !$body) {
            throw new RuntimeException("GetFriendsList: HTTP {$code}");
        }

        $data = json_decode($body, true);
        $friends = $data['response']['friendslist']['friends']
                ?? $data['response']['friends']
                ?? $data['friendslist']['friends']
                ?? [];

        $friendSids = array_map('strval', array_column($friends, 'steamid'));
        $allSet = array_flip($allSteamIds);

        $matched = [];
        foreach ($friendSids as $fid) {
            if (isset($allSet[$fid]) && $fid !== $ownSid) {
                $matched[] = $fid;
            }
        }

        return $matched;
    }

    // =========================================================================
    // HTTP helpers
    // =========================================================================

    /** POST protobuf через multipart/form-data (как SteamStoreSession). */
    private function postProtobuf(string $url, string $protoBytes, ?array $proxy): array
    {
        $boundary = '----PHP' . bin2hex(random_bytes(8));
        $body  = "--{$boundary}\r\n";
        $body .= "Content-Disposition: form-data; name=\"input_protobuf_encoded\"\r\n\r\n";
        $body .= base64_encode($protoBytes) . "\r\n";
        $body .= "--{$boundary}--\r\n";

        return $this->httpRequest('POST', $url, $body, $proxy, [
            'Accept: */*',
            'Content-Type: multipart/form-data; boundary=' . $boundary,
            'Origin: https://store.steampowered.com',
            'Referer: https://store.steampowered.com/',
        ]);
    }

    /**
     * Универсальный HTTP-запрос с поддержкой прокси и response headers.
     * @return array{code:int, body:string, headers:array<string,string>}
     */
    private function httpRequest(string $method, string $url, ?string $body, ?array $proxy, array $headers = []): array
    {
        $ch = curl_init();

        $respHeaders = [];
        $curlOpts = [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_ENCODING       => '',
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_USERAGENT      => self::UA,
            CURLOPT_HTTPHEADER     => array_merge([
                'Accept-Language: ru,en;q=0.9',
            ], $headers),
            CURLOPT_HEADERFUNCTION => function ($c, string $hline) use (&$respHeaders): int {
                $len = strlen($hline);
                $t = trim($hline);
                if ($t !== '' && strpos($t, ':') !== false) {
                    [$k, $v] = explode(':', $t, 2);
                    $respHeaders[strtolower(trim($k))] = trim($v);
                }
                return $len;
            },
        ];

        if ($method === 'POST') {
            $curlOpts[CURLOPT_POST]       = true;
            $curlOpts[CURLOPT_POSTFIELDS] = $body ?? '';
        }

        if ($proxy) {
            $scheme = strtolower((string)($proxy['scheme'] ?? 'http'));
            $curlOpts[CURLOPT_PROXY] = $proxy['host'] . ':' . (int)$proxy['port'];
            $curlOpts[CURLOPT_PROXYTYPE] = match ($scheme) {
                'socks5' => CURLPROXY_SOCKS5_HOSTNAME,
                'socks4' => CURLPROXY_SOCKS4,
                default  => CURLPROXY_HTTP,
            };
            if (!empty($proxy['username'])) {
                $curlOpts[CURLOPT_PROXYUSERPWD] = $proxy['username'] . ':' . (string)($proxy['password'] ?? '');
            }
        }

        curl_setopt_array($ch, $curlOpts);
        $respBody = curl_exec($ch);
        $err      = curl_error($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($respBody === false) {
            throw new RuntimeException("cURL: {$err}");
        }

        return ['code' => $httpCode, 'body' => (string)$respBody, 'headers' => $respHeaders];
    }

    /** Простой POST для Steam Web API (AddFriend и т.п.). */
    private function curlPost(string $url, string $body, array $extraHeaders = []): array
    {
        $ch = curl_init($url);
        $respHeaders = [];
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_USERAGENT      => self::UA,
            CURLOPT_HTTPHEADER     => array_merge([
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ], $extraHeaders),
            CURLOPT_HEADERFUNCTION => function ($c, string $hline) use (&$respHeaders): int {
                $len = strlen($hline);
                $t = trim($hline);
                if ($t !== '' && strpos($t, ':') !== false) {
                    [$k, $v] = explode(':', $t, 2);
                    $respHeaders[strtolower(trim($k))] = trim($v);
                }
                return $len;
            },
        ]);
        $respBody = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($respBody === false) {
            throw new RuntimeException("cURL: {$err}");
        }

        return ['code' => $httpCode, 'body' => (string)$respBody, 'headers' => $respHeaders];
    }

    // =========================================================================
    // RSA helpers (из SteamStoreSession)
    // =========================================================================

    private function hexRsaToPem(string $modulusHex, string $exponentHex): string
    {
        $modulus = hex2bin($modulusHex);
        $exponent = hex2bin($exponentHex);
        if ($modulus === false || $exponent === false) {
            throw new RuntimeException('RSA key hex decode failed');
        }
        if (ord($modulus[0]) & 0x80) $modulus = "\x00" . $modulus;
        if (ord($exponent[0]) & 0x80) $exponent = "\x00" . $exponent;

        $encInt = static function (string $b): string {
            return "\x02" . self::asn1Len(strlen($b)) . $b;
        };

        $rsaKey = $encInt($modulus) . $encInt($exponent);
        $rsaSeq = "\x30" . self::asn1Len(strlen($rsaKey)) . $rsaKey;

        $algOid  = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00";
        $algSeq  = "\x30" . self::asn1Len(strlen($algOid)) . $algOid;
        $bitStr  = "\x03" . self::asn1Len(strlen($rsaSeq) + 1) . "\x00" . $rsaSeq;
        $spki    = "\x30" . self::asn1Len(strlen($algSeq) + strlen($bitStr)) . $algSeq . $bitStr;

        return "-----BEGIN PUBLIC KEY-----\n"
             . chunk_split(base64_encode($spki), 64, "\n")
             . "-----END PUBLIC KEY-----\n";
    }

    private static function asn1Len(int $len): string
    {
        if ($len < 0x80) return chr($len);
        $hex = dechex($len);
        if (strlen($hex) % 2) $hex = '0' . $hex;
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

        // SteamProtobufCodec — обязателен для protobuf-авторизации
        $protoPaths = [
            $projectRoot . '/steamtopup/steam_topup/SteamProtobufCodec.php',
            $projectRoot . '/test/steam_gift_region_checker/steam_topup/SteamProtobufCodec.php',
            $checkerRoot . '/steam_topup/SteamProtobufCodec.php',
        ];
        // SteamCrypto — расшифровка пароля из БД
        $cryptoPaths = [
            $projectRoot . '/steamtopup/steam_topup/SteamAccountsRepo.php',
            $projectRoot . '/test/steam_gift_region_checker/steam_topup/SteamAccountsRepo.php',
            $checkerRoot . '/steam_topup/SteamAccountsRepo.php',
        ];

        $dir = $projectRoot;
        for ($i = 0; $i < 4; $i++) {
            $protoPaths[]  = $dir . '/steamtopup/steam_topup/SteamProtobufCodec.php';
            $protoPaths[]  = $dir . '/steam_topup/SteamProtobufCodec.php';
            $cryptoPaths[] = $dir . '/steamtopup/steam_topup/SteamAccountsRepo.php';
            $cryptoPaths[] = $dir . '/steam_topup/SteamAccountsRepo.php';
            $parent = dirname($dir);
            if ($parent === $dir) break;
            $dir = $parent;
        }

        if (!class_exists('SteamProtobufCodec', false)) {
            foreach (array_unique($protoPaths) as $path) {
                if (is_file($path)) { require_once $path; break; }
            }
        }
        $this->protobufLoaded = class_exists('SteamProtobufCodec', false);

        if (!class_exists('SteamCrypto', false)) {
            foreach (array_unique($cryptoPaths) as $path) {
                if (is_file($path)) { require_once $path; break; }
            }
        }
        $this->cryptoLoaded = class_exists('SteamCrypto', false);
    }

    /** Прокси из аккаунта или null. */
    private function loadProxyForAccount(array $account): ?array
    {
        if (empty($account['proxy_id']) || !$this->pdo) return null;
        return $this->loadProxy((int)$account['proxy_id']);
    }

    private function loadProxy(int $proxyId): ?array
    {
        if (!$this->pdo) return null;
        try {
            $stmt = $this->pdo->prepare('SELECT * FROM steam_proxies WHERE id = ? AND active = 1');
            $stmt->execute([$proxyId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable) { return null; }
        if (!$row) return null;
        return [
            'scheme'   => $row['scheme'] ?? 'http',
            'host'     => $row['host'],
            'port'     => (int)$row['port'],
            'username' => $row['username'] ?? null,
            'password' => $row['password'] ?? null,
        ];
    }

    // =========================================================================
    // Кэш invite-токенов (приватно, не попадает в UI)
    // =========================================================================

    private function inviteTokensFile(): string
    {
        return $this->logDir . '/invite_tokens.json';
    }

    /** @return array<string, array{invite_token:string,time_created?:int,invite_limit?:int,valid?:bool}> */
    private function loadInviteTokens(): array
    {
        $f = $this->inviteTokensFile();
        if (!is_file($f)) return [];
        $raw = @file_get_contents($f);
        if ($raw === false || $raw === '') return [];
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    private function saveInviteToken(string $steamid, string $inviteToken, array $meta = []): void
    {
        $tokens = $this->loadInviteTokens();
        $tokens[$steamid] = array_merge(
            ['invite_token' => $inviteToken, 'saved_at' => date('Y-m-d H:i:s')],
            $meta
        );
        $f = $this->inviteTokensFile();
        @file_put_contents(
            $f,
            json_encode($tokens, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT),
            LOCK_EX
        );
        @chmod($f, 0600);
    }

    private function forgetInviteToken(string $steamid): void
    {
        $tokens = $this->loadInviteTokens();
        if (!isset($tokens[$steamid])) return;
        unset($tokens[$steamid]);
        $f = $this->inviteTokensFile();
        @file_put_contents(
            $f,
            json_encode($tokens, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT),
            LOCK_EX
        );
        @chmod($f, 0600);
    }

    // =========================================================================
    // Protobuf helpers
    // =========================================================================

    /**
     * Кодирование fixed64 (wire-type 1, 8 байт little-endian).
     * SteamProtobufCodec в проекте не имеет fixed64-хелпера, но он нужен
     * для steamid в RedeemFriendInviteToken_Request.
     */
    private static function encodeFixed64(int $field, string $value): string
    {
        $tag  = chr(($field << 3) | 1);
        $val  = (int)$value; // steamid64 ≈ 7.6e16, помещается в 64-bit PHP int
        $low  = $val & 0xFFFFFFFF;
        $high = ($val >> 32) & 0xFFFFFFFF;
        return $tag . pack('VV', $low, $high);
    }

    // =========================================================================
    // Logging
    // =========================================================================

    /** Безопасно логировать тело ответа (может быть protobuf/бинарное). */
    private function safeLogBody(string $body, int $maxLen = 300): string
    {
        if ($body === '') return '(empty)';
        if (json_decode($body, true) !== null) return mb_substr($body, 0, $maxLen);
        if (preg_match('/[^\x20-\x7E\r\n\t]/', $body)) {
            return '(binary ' . strlen($body) . 'b)';
        }
        return mb_substr($body, 0, $maxLen);
    }

    /**
     * Свести любую ошибку к короткой однострочной форме без HTML/бинарных
     * хвостов. Используется и в логе, и в ответе API.
     */
    private function shortError(string $msg): string
    {
        $msg = trim($msg);
        // Срезаем HTML-страницы целиком: «<html…»
        if (preg_match('~^(.*?)<\s*/?\s*html\b~is', $msg, $m)) {
            $msg = trim($m[1]);
        }
        // Убираем повторяющиеся пробелы и переводы строк
        $msg = preg_replace('/\s+/', ' ', $msg);
        // Ограничиваем длину
        if (mb_strlen($msg) > 160) {
            $msg = mb_substr($msg, 0, 160) . '…';
        }
        return $msg !== '' ? $msg : 'unknown error';
    }

    private function log(string $msg): void
    {
        $line = date('Y-m-d H:i:s') . " [FriendMgr] {$msg}\n";
        @file_put_contents($this->logDir . '/friends_' . date('Y-m-d') . '.log', $line, FILE_APPEND);
    }
}
