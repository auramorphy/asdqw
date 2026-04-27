<?php
declare(strict_types=1);

/**
 * SteamFriendManager — добавление Steam-аккаунтов чекеров в друзья друг к другу.
 *
 * Поток через quick-invite link (s.team/p/<short>/<token>):
 *   1. Каждый аккаунт логинится через Steam Auth protobuf API → access_token (JWT).
 *   2. Из access_token собирается cookie-сессия steamcommunity.com:
 *        sessionid        = случайные 24 hex
 *        steamLoginSecure = "<steamid64>||<jwt>" (URL-encoded)
 *   3. Для каждого аккаунта один раз GET https://steamcommunity.com/my/
 *      и из data-userinfo берём short_url ("https://s.team/p/<short>") —
 *      это персональный префикс quick-invite ссылки.
 *   4. Для каждой пары (A → B):
 *        a) A POST https://steamcommunity.com/invites/ajaxcreate
 *           body: sessionid, steamid_user=<A>, duration=2592000
 *           response: {data: {invite: {invite_token: "<секрет>"}}}
 *        b) B GET <A.short_url>/<invite_token>  (s.team/p/<short>/<token>)
 *           Steam редиректит на /user/<short>/<token>/ и серверно
 *           регистрирует дружбу A↔B (одноразово, токен сжигается).
 *        c) Финальный URL после редиректа разбираем:
 *             /profiles/<A>/  или /id/<A_vanity>/  → invite_redeemed
 *             /login/...                            → access_denied
 *             прочее с keyword Expired/Invalid      → invite_expired / invalid_invite
 *
 *   Quick-invite ссылка (ни сам токен, ни short_url) НИГДЕ не выводится —
 *   ни в UI/HTML, ни в логах. Существует только в памяти между шагами 4a и 4b.
 *
 * Почему не api.steampowered.com:
 *   - IFriendsListService/AddFriend/v1/               → HTTP 404 (удалён)
 *   - IUserAccountService/CreateFriendInviteToken/v1/ → HTTP 404
 *   - IUserAccountService/RedeemFriendInviteToken/v1/ → HTTP 404
 *   Эти методы живут только в .steamclient.proto (Steam binary CM-протокол),
 *   на Web API они не выставлены — см. список IUserAccountService на
 *   https://steamapi.xpaw.me/. Реальные web-эндпоинты quick-invite:
 *   POST steamcommunity.com/invites/ajaxcreate (mint),
 *   GET  steamcommunity.com/user/<short>/<token>/ (server-side redeem).
 *
 * Fallback: если apiCreateInviteToken/apiRedeemQuickInvite вернули ошибку —
 * пробуем тот же AddFriendAjax, который Steam использует на странице поиска
 * друзей (это не «удалённый api.steampowered.com endpoint», а живой
 * cookie-action на steamcommunity.com).
 *
 * Зависимости:
 *   - SteamProtobufCodec (protobuf encode/decode для login-флоу)
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
    // Добавление в друзья через quick-invite link (s.team/p/<short>/<token>)
    // =========================================================================

    /**
     * Кэш живых cookie-сессий внутри одного add_one запроса:
     *   steamid64 → ['session' => [...], 'short_url' => string, 'proxy' => array|null]
     * Чтобы не логиниться повторно для каждой пары.
     */
    private array $sessionCache = [];

    /**
     * Залогиниться (если ещё не) и вернуть подготовленную cookie-сессию + short_url
     * для аккаунта по его steamid64. $allAccounts — список строк steam_checker_accounts.
     *
     * @return array{session: array, short_url: string, proxy: ?array}
     */
    private function ensureAccountSession(array $account): array
    {
        $sid = (string)($account['steamid64'] ?? '');
        if ($sid !== '' && isset($this->sessionCache[$sid])) {
            return $this->sessionCache[$sid];
        }

        $auth     = $this->loginAndGetToken($account);
        $proxy    = $this->loadProxyForAccount($account);
        $loginSid = $auth['steamId'] ?: $sid;
        $session  = $this->buildCommunitySession($loginSid, $auth['token']);
        $shortUrl = $this->apiFetchOwnShortUrl($session, $proxy);

        $entry = ['session' => $session, 'short_url' => $shortUrl, 'proxy' => $proxy];
        if ($loginSid !== '') $this->sessionCache[$loginSid] = $entry;
        if ($sid !== '' && $sid !== $loginSid) $this->sessionCache[$sid] = $entry;
        return $entry;
    }

    /**
     * Главная точка: для одного аккаунта (A) добавить в друзья всех target-ов.
     * На каждой паре (A → B):
     *   1. A создаёт одноразовый invite_token через invites/ajaxcreate.
     *   2. B (логинится из $allAccounts) переходит по A.short_url/<token>.
     *   3. Финальный URL разбираем: profiles/<A>/ или id/<vanity>/ → redeemed,
     *      /login/ → access_denied, expired/invalid → invite_expired / invalid_invite.
     * Если quick-invite шаги (a) или (b) дали ошибку — fallback на AddFriendAjax,
     * чтобы пара всё равно была соединена (Steam-friend status симметричен).
     *
     * @param array       $account     Строка steam_checker_accounts (источник, A)
     * @param string[]    $targetSteamIds steamid64 всех целей
     * @param array       $allAccounts Все строки steam_checker_accounts (для логина B)
     * @param callable|null $onProgress function(string $message)
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

        // карта steamid → строка аккаунта (для логина B)
        $byId = [];
        foreach ($allAccounts as $a) {
            $sid = (string)($a['steamid64'] ?? '');
            if ($sid !== '') $byId[$sid] = $a;
        }
        if ($ownSid !== '' && !isset($byId[$ownSid])) $byId[$ownSid] = $account;

        // login A
        try {
            $A = $this->ensureAccountSession($account);
        } catch (Throwable $e) {
            $msg = $this->shortError($e->getMessage());
            $results['errors'][] = ['target' => '*', 'error' => "login_failed: {$msg}"];
            $this->log("addFriends {$login} steamId={$ownSid}: login_failed: {$msg}");
            return $results;
        }
        $loginSid = $A['session']['steamid'] ?: $ownSid;
        if ($onProgress) $onProgress("✅ {$login}: залогинен (steamId={$loginSid})");

        foreach ($targetSteamIds as $targetSid) {
            $targetSid = (string)$targetSid;
            if ($targetSid === '' || $targetSid === $loginSid || $targetSid === $ownSid) continue;

            try {
                $status = $this->addOnePair($A, $targetSid, $byId, $login);
            } catch (Throwable $e) {
                $status = 'failed:' . $this->shortError($e->getMessage());
            }

            $isOk = in_array($status, ['invite_redeemed', 'invite_sent', 'already_friends', 'pending'], true);
            if ($isOk) {
                $results['sent'][] = ['target' => $targetSid, 'result' => $status];
                $this->log("addFriends {$login} → {$targetSid}: {$status}");
                if ($onProgress) $onProgress("  ✓ {$targetSid}: {$status}");
            } else {
                $results['errors'][] = ['target' => $targetSid, 'error' => $status];
                $this->log("addFriends {$login} → {$targetSid}: {$status}");
                if ($onProgress) $onProgress("  ✕ {$targetSid}: {$status}");
            }

            usleep(random_int(400_000, 1_200_000));
        }

        return $results;
    }

    /**
     * Один полный шаг A→B: mint quick-invite token у A, redeem у B; если
     * не получилось — пробуем AddFriendAjax. Возвращаем итоговый статус.
     */
    private function addOnePair(array $A, string $targetSid, array $byId, string $logLogin): string
    {
        // 1. Пытаемся через quick-invite link
        $token = '';
        try {
            $token = $this->apiCreateInviteToken($A['session'], $A['proxy']);
        } catch (Throwable $e) {
            $this->log("addFriends {$logLogin} → {$targetSid}: create_invite_failed: " . $this->shortError($e->getMessage()));
        }

        if ($token !== '' && isset($byId[$targetSid])) {
            try {
                $B = $this->ensureAccountSession($byId[$targetSid]);
                $status = $this->apiRedeemQuickInvite(
                    $B['session'], $A['short_url'], $token, $A['session']['steamid'], $B['proxy']
                );
                // финальные «успешные» статусы — возвращаем сразу
                if (in_array($status, ['invite_redeemed', 'already_friends'], true)) {
                    return $status;
                }
                // expired / invalid — токен сжёг себя или невалиден; для B уже не починить
                if ($status === 'invite_expired' || $status === 'invalid_invite') {
                    // продолжим в fallback ниже — может AddFriendAjax всё-таки сработает
                    $this->log("addFriends {$logLogin} → {$targetSid}: redeem={$status}, fallback to AddFriendAjax");
                } elseif ($status === 'access_denied') {
                    // у B отвалилась cookie-сессия — fallback тоже бесполезен от B,
                    // но AddFriendAjax от A может закрыть пару висящей заявкой
                    $this->log("addFriends {$logLogin} → {$targetSid}: redeem=access_denied, fallback to AddFriendAjax");
                }
            } catch (Throwable $e) {
                $this->log("addFriends {$logLogin} → {$targetSid}: redeem_failed: " . $this->shortError($e->getMessage()));
            }
        }

        // 2. Fallback: cookie-action AddFriendAjax от лица A
        return $this->apiAddFriendCommunity($A['session'], $targetSid, $A['proxy']);
    }

    /**
     * Собирает данные cookie-сессии для steamcommunity.com из access_token.
     * sessionid генерируется локально; steamLoginSecure имеет формат
     * "<steamid64>||<jwt access_token>" (URL-encoded), как и у официального
     * клиента / store.steampowered.com.
     *
     * @return array{sessionid:string,steam_login_secure:string,steamid:string}
     */
    private function buildCommunitySession(string $steamId, string $accessToken): array
    {
        return [
            'sessionid'          => bin2hex(random_bytes(12)),
            'steam_login_secure' => $steamId . '||' . $accessToken,
            'steamid'            => $steamId,
        ];
    }

    /**
     * Сторка cookie для steamcommunity.com.
     */
    private function communityCookieHeader(array $session): string
    {
        return 'sessionid=' . $session['sessionid']
             . '; steamLoginSecure=' . rawurlencode($session['steam_login_secure']);
    }

    /**
     * GET https://steamcommunity.com/my/ → парсим data-userinfo → short_url.
     * short_url имеет вид "https://s.team/p/<encoded>" (персональный префикс).
     * Если поле пустое — вернём '' (тогда quick-invite flow не сработает,
     * упадём на fallback AddFriendAjax).
     */
    private function apiFetchOwnShortUrl(array $session, ?array $proxy): string
    {
        $resp = $this->httpRequest('GET', 'https://steamcommunity.com/my/', null, $proxy, [
            'Accept: text/html,*/*',
            'Cookie: ' . $this->communityCookieHeader($session),
        ]);
        // /my/ редиректит на /profiles/<id>/, нам важен любой ответ с data-userinfo
        if ($resp['code'] === 302 && !empty($resp['headers']['location'])) {
            $resp = $this->httpRequest('GET', $resp['headers']['location'], null, $proxy, [
                'Accept: text/html,*/*',
                'Cookie: ' . $this->communityCookieHeader($session),
            ]);
        }
        if ($resp['code'] !== 200 || $resp['body'] === '') return '';

        if (preg_match('/data-userinfo="([^"]+)"/', $resp['body'], $m)) {
            $json = html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5);
            $info = json_decode($json, true);
            if (is_array($info) && !empty($info['short_url'])) {
                return (string)$info['short_url'];
            }
        }
        return '';
    }

    /**
     * POST https://steamcommunity.com/invites/ajaxcreate
     *   body: sessionid, steamid_user=<own>, duration=2592000
     *   resp: {"success":1,"data":{"invite":{"invite_token":"<секрет>", ...}}}
     * Возвращает invite_token (строка) или бросает RuntimeException.
     */
    private function apiCreateInviteToken(array $session, ?array $proxy): string
    {
        $body = http_build_query([
            'sessionid'    => $session['sessionid'],
            'steamid_user' => $session['steamid'],
            'duration'     => '2592000', // 30 дней (как делает /friends/add)
        ]);
        $resp = $this->httpRequest('POST', 'https://steamcommunity.com/invites/ajaxcreate', $body, $proxy, [
            'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
            'Accept: application/json, text/plain, */*',
            'X-Requested-With: XMLHttpRequest',
            'Origin: https://steamcommunity.com',
            'Referer: https://steamcommunity.com/profiles/' . $session['steamid'] . '/friends/add',
            'Cookie: ' . $this->communityCookieHeader($session),
        ]);

        if ($resp['code'] === 401 || $resp['code'] === 403) {
            throw new RuntimeException('create_invite: access_denied (HTTP ' . $resp['code'] . ')');
        }

        $data = json_decode($resp['body'] ?: '', true);
        if (!is_array($data)) {
            throw new RuntimeException('create_invite: HTTP ' . $resp['code'] . ' (non-JSON)');
        }
        $tok = $data['data']['invite']['invite_token']
            ?? $data['invite']['invite_token']
            ?? '';
        if (!is_string($tok) || $tok === '') {
            throw new RuntimeException('create_invite: no invite_token in response');
        }
        return $tok;
    }

    /**
     * GET <short_url>/<invite_token>  (== https://s.team/p/<short>/<token>)
     * под cookie-сессией B. s.team редиректит на steamcommunity.com/user/<short>/<token>/,
     * Steam серверно регистрирует дружбу A↔B, после чего обычно редиректит
     * на /profiles/<A>/ или /id/<A_vanity>/.
     *
     * Различаем итог по финальному URL после всех редиректов:
     *   /profiles/<A>/ или /id/<A_vanity>/         → invite_redeemed (или already_friends)
     *   /login/                                     → access_denied
     *   /user/<short>/<token>/ + body «invalid»     → invalid_invite
     *   /user/<short>/<token>/ + body «expired»     → invite_expired
     *   прочее                                       → community_error=redeem_unknown
     *
     * Чтобы отличить already_friends от свежей подписки, после редиректа
     * проверяем title/тело: уже-в-друзьях не ловим напрямую → возвращаем
     * 'invite_redeemed', а уже-в-друзьях нам всё равно подтвердит «🔍 Проверить друзей».
     */
    private function apiRedeemQuickInvite(
        array $bSession, string $aShortUrl, string $token, string $aSteamId, ?array $proxy
    ): string {
        if ($aShortUrl === '' || $token === '') {
            return 'invalid_invite';
        }
        $url = rtrim($aShortUrl, '/') . '/' . $token;

        $cookie = $this->communityCookieHeader($bSession);
        $maxRedirects = 6;
        $finalUrl  = $url;
        $finalBody = '';
        $finalCode = 0;

        for ($i = 0; $i < $maxRedirects; $i++) {
            $resp = $this->httpRequest('GET', $finalUrl, null, $proxy, [
                'Accept: text/html,application/xhtml+xml,*/*',
                'Cookie: ' . $cookie,
            ]);
            $finalCode = $resp['code'];
            $finalBody = $resp['body'];
            if ($resp['code'] >= 300 && $resp['code'] < 400 && !empty($resp['headers']['location'])) {
                $loc = $resp['headers']['location'];
                if ($loc[0] === '/') $loc = $this->absUrl($finalUrl, $loc);
                $finalUrl = $loc;
                continue;
            }
            break;
        }

        // редирект на login → cookie-сессия B не принята
        if (str_contains($finalUrl, '/login/')) return 'access_denied';

        // финальный URL — профиль A (по steamid64 или по vanity)
        if (preg_match('#/profiles/' . preg_quote($aSteamId, '#') . '/?#', $finalUrl)) {
            return 'invite_redeemed';
        }
        if (preg_match('#/id/[^/]+/?$#', $finalUrl)) {
            // /id/<vanity>/ — почти всегда профиль A после редемпшена
            return 'invite_redeemed';
        }

        // остались на /user/<short>/<token>/ — токен не отработал
        $body = strtolower($finalBody);
        if (str_contains($body, 'expired')) return 'invite_expired';
        if (str_contains($body, 'invalid') || str_contains($body, 'no longer valid')) return 'invalid_invite';
        if (str_contains($body, 'already')) return 'already_friends';

        if ($finalCode !== 200) return 'community_error=redeem_http_' . $finalCode;
        return 'community_error=redeem_unknown';
    }

    private function absUrl(string $base, string $relative): string
    {
        if (preg_match('#^https?://#i', $relative)) return $relative;
        $p = parse_url($base);
        $scheme = $p['scheme'] ?? 'https';
        $host   = $p['host']   ?? 'steamcommunity.com';
        if ($relative[0] !== '/') $relative = '/' . $relative;
        return $scheme . '://' . $host . $relative;
    }

    /**
     * POST https://steamcommunity.com/actions/AddFriendAjax  (fallback).
     *
     * Используется только если apiCreateInviteToken / apiRedeemQuickInvite
     * не сработали (например, не залогинен B, у A нет короткой ссылки и т.п.).
     * Это не «удалённый api.steampowered.com endpoint», а живой cookie-action
     * на steamcommunity.com (тот же путь, что нажатие «Добавить» в UI Steam).
     *
     * @return string один из: 'invite_sent' | 'already_friends' | 'pending'
     *                | 'rate_limited' | 'blocked' | 'limit_exceeded'
     *                | 'access_denied' | 'failed' | "community_error=N"
     */
    private function apiAddFriendCommunity(array $session, string $targetSteamId, ?array $proxy): string
    {
        $url     = 'https://steamcommunity.com/actions/AddFriendAjax';
        $body    = http_build_query([
            'sessionID'      => $session['sessionid'],
            'steamid'        => $targetSteamId,
            'accept_invite'  => '0',
        ]);

        $headers = [
            'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
            'Accept: application/json, text/plain, */*',
            'X-Requested-With: XMLHttpRequest',
            'Origin: https://steamcommunity.com',
            'Referer: https://steamcommunity.com/profiles/' . $session['steamid'] . '/friends/',
            'Cookie: ' . $this->communityCookieHeader($session),
        ];

        $resp = $this->httpRequest('POST', $url, $body, $proxy, $headers);

        if ($resp['code'] === 401 || $resp['code'] === 403) return 'access_denied';
        if ($resp['code'] === 429) return 'rate_limited';

        $data = json_decode($resp['body'] ?: '', true);
        if (!is_array($data)) return 'community_error=invalid_session';

        if (!empty($data['success']) && empty($data['failed_invites'])) return 'invite_sent';

        $codes = (array)($data['failed_invites_result'] ?? []);
        $code  = isset($codes[0]) ? (int)$codes[0] : 0;

        return match ($code) {
            0   => 'failed',
            11  => 'pending',
            14  => 'already_friends',
            15  => 'access_denied',
            24  => 'rate_limited',
            25  => 'limit_exceeded',
            33  => 'pending',
            40  => 'blocked',
            41  => 'blocked',
            84  => 'rate_limited',
            default => "community_error={$code}",
        };
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
