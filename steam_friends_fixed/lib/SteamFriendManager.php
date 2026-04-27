<?php
declare(strict_types=1);

/**
 * SteamFriendManager — добавление Steam-аккаунтов чекеров в друзья друг к другу.
 *
 * Поток через quick-invite link (s.team/p/<short>/<token>):
 *   1. Каждый аккаунт логинится (RSA → BeginAuth → PollAuth → refresh_token + access_token).
 *   2. POST https://login.steampowered.com/jwt/finalizelogin (с refresh_token)
 *      → transfer_info[i] для каждого домена (store/help/checkout/community).
 *      Для steamcommunity.com POST его {steamID/nonce/auth} на settoken-URL —
 *      сервер ставит Set-Cookie steamLoginSecure=<JWT для community> в ответе.
 *      Эту cookie используем как community-сессию (синтетический "<sid>||<jwt>"
 *      от api.steampowered.com community.com не принимает — другая audience).
 *   3. Один раз парсим data-userinfo на /my/ → short_url ("https://s.team/p/<encoded>")
 *      — персональный префикс quick-invite ссылки A.
 *   4. На каждой паре (A → B):
 *        a) A POST https://steamcommunity.com/invites/ajaxcreate
 *           body: sessionid, steamid_user=<A>, duration=2592000
 *           → одноразовый invite_token.
 *        b) B (логинится из $allAccounts) GET <A.short_url>/<invite_token>
 *           под своими community-cookies. s.team редиректит на /user/<short>/<token>/,
 *           Steam серверно регистрирует обоюдную дружбу A↔B и сжигает токен.
 *        c) Финальный URL после редиректов разбираем:
 *             /profiles/<A>/  или /id/<A_vanity>/  → invite_redeemed
 *             /login/...                            → access_denied
 *             body: expired/invalid/already         → invite_expired / invalid_invite / already_friends
 *
 * Quick-invite ссылка (ни сам токен, ни short_url) НИГДЕ не выводится —
 * ни в UI/HTML, ни в логах. Существует только в памяти между шагами 4a и 4b.
 *
 * Почему НЕ через AddFriendAjax / api.steampowered.com:
 *   - api.steampowered.com IFriendsListService/AddFriend и
 *     IUserAccountService/(Create|Redeem)FriendInviteToken на Web API не выставлены
 *     (живут только в .steamclient.proto, см. https://steamapi.xpaw.me/).
 *   - actions/AddFriendAjax агрессивно лимитится по IP/аккаунту:
 *     уже после нескольких заявок Steam отвечает rate_limited на всё.
 *   - quick-invite (invites/ajaxcreate + GET /user/<short>/<token>/) — это путь,
 *     который Steam использует на странице /friends/add своего веб-UI;
 *     он не упирается в тот же rate-limit, потому что это разные эндпоинты.
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

        // Step 4. PollAuthSessionStatus → access_token + refresh_token
        $tokens = $this->pollAuthSessionFull($clientId, $requestId, $proxy);
        $accessToken  = $tokens['access_token'];
        $refreshToken = $tokens['refresh_token'];
        $this->log("LOGIN step4 tokens ok, access_len=" . strlen($accessToken)
                 . " refresh_len=" . strlen($refreshToken));

        if ($refreshToken === '') {
            throw new RuntimeException('Не получен refresh_token из PollAuthSession');
        }

        // Step 5. finalizelogin (refresh_token → transfer_info)
        // + settoken на steamcommunity.com (transfer_info → server-issued steamLoginSecure cookie).
        // Только так Steam примет нашу cookie-сессию на community.com (синтетический
        // "<sid>||<jwt>" не работает — там JWT с другой audience).
        $sid = bin2hex(random_bytes(12));
        try {
            $transferInfo = $this->finalizeLogin($refreshToken, $sid, $proxy);
            $sls = $this->acquireSteamLoginSecure(
                $steamId, $transferInfo, 'steamcommunity.com', $proxy
            );
            $this->log("LOGIN step5 community steamLoginSecure ok, len=" . strlen($sls));
        } catch (Throwable $e) {
            // Если settoken упал — quick-invite flow не сработает. Бросаем ошибку явно,
            // чтобы add_one не делал бесполезных запросов в community с битой сессией.
            throw new RuntimeException('finalizelogin/settoken: ' . $this->shortError($e->getMessage()));
        }

        return [
            'token'         => $accessToken,
            'refresh_token' => $refreshToken,
            'steamId'       => $steamId,
            // готовая cookie-сессия для steamcommunity.com (server-issued)
            'community_session' => [
                'sessionid'          => $sid,
                'steam_login_secure' => $sls,
                'steamid'            => $steamId,
            ],
        ];
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
     * Step 4: PollAuthSessionStatus — получаем оба токена.
     *
     * Ответ PollAuthSessionStatus содержит:
     *   field 3 = refresh_token (нужен для finalizelogin → cookie steamcommunity.com)
     *   field 4 = access_token  (нужен для api.steampowered.com / IFriendsListService)
     *
     * Возвращаем оба. Если field 4 пуст — генерируем access из refresh
     * через GenerateAccessTokenForApp.
     *
     * @return array{access_token: string, refresh_token: string}
     */
    private function pollAuthSessionFull(int $clientId, string $requestId, ?array $proxy): array
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
            $refreshToken = isset($decoded[3]) && is_string($decoded[3]) ? $decoded[3] : '';
            $accessToken  = isset($decoded[4]) && is_string($decoded[4]) ? $decoded[4] : '';

            if ($refreshToken !== '') {
                if ($accessToken === '') {
                    $this->log("PollAuth: got refresh_token but no access_token, generating");
                    $accessToken = (string)$this->generateAccessTokenFromRefresh($refreshToken, $proxy);
                }
                return ['access_token' => $accessToken, 'refresh_token' => $refreshToken];
            }

            usleep($delayMs * 1000);
        }

        throw new RuntimeException('PollAuth: за ' . ($maxAttempts * $delayMs / 1000) . 'с не получен refresh_token');
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

    /**
     * Step 5a: POST https://login.steampowered.com/jwt/finalizelogin
     *   multipart: nonce=<refresh_token>, sessionid=<sid>, redir=https://store.steampowered.com/login/
     * Возвращает массив transfer_info: для каждого домена (store/checkout/help/community)
     * свой URL + nonce/auth, которые надо POST'нуть на этот URL чтобы получить
     * Set-Cookie steamLoginSecure от самого сервера домена.
     *
     * @return array<int, array{url: string, nonce: string, auth: string}>
     */
    private function finalizeLogin(string $refreshToken, string $sessionId, ?array $proxy): array
    {
        $boundary = '----PHP' . bin2hex(random_bytes(8));
        $body = '';
        foreach ([
            'nonce'     => $refreshToken,
            'sessionid' => $sessionId,
            'redir'     => 'https://store.steampowered.com/login/',
        ] as $k => $v) {
            $body .= "--{$boundary}\r\n";
            $body .= "Content-Disposition: form-data; name=\"{$k}\"\r\n\r\n";
            $body .= $v . "\r\n";
        }
        $body .= "--{$boundary}--\r\n";

        $resp = $this->httpRequest('POST', 'https://login.steampowered.com/jwt/finalizelogin', $body, $proxy, [
            'Accept: application/json, text/plain, */*',
            'Content-Type: multipart/form-data; boundary=' . $boundary,
            'Origin: https://store.steampowered.com',
            'Referer: https://store.steampowered.com/',
        ]);
        if ($resp['code'] < 200 || $resp['code'] >= 300) {
            throw new RuntimeException("finalizelogin: HTTP {$resp['code']}");
        }
        $data = json_decode($resp['body'] ?: '', true);
        if (!is_array($data) || empty($data['transfer_info']) || !is_array($data['transfer_info'])) {
            throw new RuntimeException('finalizelogin: нет transfer_info в ответе');
        }
        $out = [];
        foreach ($data['transfer_info'] as $ti) {
            $url    = (string)($ti['url'] ?? '');
            $params = $ti['params'] ?? [];
            if ($url === '' || !is_array($params)) continue;
            $out[] = [
                'url'   => $url,
                'nonce' => (string)($params['nonce'] ?? ''),
                'auth'  => (string)($params['auth'] ?? ''),
            ];
        }
        if (!$out) throw new RuntimeException('finalizelogin: transfer_info пуст после разбора');
        return $out;
    }

    /**
     * Step 5b: POST на нужный transfer_info URL (например, https://steamcommunity.com/login/settoken)
     *   form-urlencoded: steamID=<sid>, nonce=<...>, auth=<...>
     * Steam в ответ ставит Set-Cookie steamLoginSecure=<jwt> для своего домена.
     * Возвращаем значение этой cookie (URL-encoded форма для прямого использования
     * в Cookie заголовке).
     */
    private function acquireSteamLoginSecure(
        string $steamId, array $transferInfo, string $domainContains, ?array $proxy
    ): string {
        foreach ($transferInfo as $t) {
            if (stripos($t['url'], $domainContains) === false) continue;

            $body = http_build_query([
                'steamID' => $steamId,
                'nonce'   => $t['nonce'],
                'auth'    => $t['auth'],
            ]);
            $resp = $this->httpRequest('POST', $t['url'], $body, $proxy, [
                'Accept: application/json',
                'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
                'Origin: https://store.steampowered.com',
                'Referer: https://store.steampowered.com/',
            ]);
            if ($resp['code'] < 200 || $resp['code'] >= 300) {
                throw new RuntimeException("settoken {$domainContains}: HTTP {$resp['code']}");
            }
            $cookies = $resp['headers']['set-cookie'] ?? [];
            if (!is_array($cookies)) $cookies = [$cookies];
            foreach ($cookies as $c) {
                if (preg_match('/^steamLoginSecure=([^;]+)/i', $c, $m)) {
                    return $m[1]; // уже URL-encoded — кладём как есть в Cookie header
                }
            }
            throw new RuntimeException("settoken {$domainContains}: нет steamLoginSecure в Set-Cookie");
        }
        throw new RuntimeException("finalizelogin: нет transfer_info для {$domainContains}");
    }

    // =========================================================================
    // Добавление в друзья: quick-invite link s.team/p/<short>/<token>
    // =========================================================================

    /**
     * Кэш живой cookie-сессии и short_url аккаунта внутри одного add_one запроса.
     *   steamid64 → [
     *     'session' => ['sessionid','steam_login_secure','steamid'],
     *     'proxy'   => ?array,
     *     'token'   => string (access_token),
     *     'short_url' => string ("https://s.team/p/<short>"), пусто пока не загружено
     *   ]
     */
    private array $sessionCache = [];

    /**
     * Залогиниться (через RSA + BeginAuth + PollAuth + finalizelogin + settoken)
     * и кэшировать community cookie-сессию + access_token.
     */
    private function ensureAccountSession(array $account): array
    {
        $sid = (string)($account['steamid64'] ?? '');
        if ($sid !== '' && isset($this->sessionCache[$sid])) {
            return $this->sessionCache[$sid];
        }
        $auth      = $this->loginAndGetToken($account); // вернёт community_session
        $proxy     = $this->loadProxyForAccount($account);
        $loginSid  = $auth['steamId'] ?: $sid;
        $session   = $auth['community_session'];
        if (empty($session['steamid'])) $session['steamid'] = $loginSid;

        $entry = [
            'session'  => $session,
            'proxy'    => $proxy,
            'token'    => $auth['token'],
            'short_url'=> '', // ленивая загрузка в apiFetchOwnShortUrl
        ];
        if ($loginSid !== '') $this->sessionCache[$loginSid] = $entry;
        if ($sid !== '' && $sid !== $loginSid) $this->sessionCache[$sid] = $entry;
        return $entry;
    }

    /**
     * Главная точка: A создаёт quick-invite ссылку, остальные аккаунты
     * (B из $allAccounts) погашают её серверно. На каждой паре свой
     * одноразовый токен — после первого редемпшена он сжигается.
     *
     * Ссылка нигде не отдаётся наружу — ни в UI/HTML, ни в логах.
     * В логах остаются только короткие статусы.
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

        // карта steamid64 → строка аккаунта (для логина B)
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

        // Прогрев — short_url у A нужен для всех redeem'ов.
        try {
            $A['short_url'] = $this->apiFetchOwnShortUrl($A['session'], $A['proxy']);
            if ($A['short_url'] === '') {
                throw new RuntimeException('apiFetchOwnShortUrl: пустой short_url (cookie не принят community)');
            }
            // обновляем кэш
            $this->sessionCache[$loginSid] = $A;
            if ($ownSid !== '' && $ownSid !== $loginSid) $this->sessionCache[$ownSid] = $A;
        } catch (Throwable $e) {
            $msg = $this->shortError($e->getMessage());
            $results['errors'][] = ['target' => '*', 'error' => "short_url_failed: {$msg}"];
            $this->log("addFriends {$login} steamId={$loginSid}: short_url_failed: {$msg}");
            return $results;
        }

        // Друзья A — чтобы не тратить запрос на already_friends.
        $friendSet = [];
        try {
            $friendSet = $this->fetchFriendSetByToken($A['token']);
        } catch (Throwable $e) {
            $this->log("addFriends {$login}: fetch_friends_failed: " . $this->shortError($e->getMessage()));
        }

        foreach ($targetSteamIds as $targetSid) {
            $targetSid = (string)$targetSid;
            if ($targetSid === '' || $targetSid === $loginSid || $targetSid === $ownSid) continue;

            // already friends → ничего не шлём в Steam
            if (isset($friendSet[$targetSid])) {
                $results['sent'][] = ['target' => $targetSid, 'result' => 'already_friends'];
                $this->log("addFriends {$login} → {$targetSid}: already_friends (cached)");
                if ($onProgress) $onProgress("  ✓ {$targetSid}: already_friends");
                continue;
            }

            try {
                $status = $this->addOnePair($A, $targetSid, $byId, $login);
            } catch (Throwable $e) {
                $status = 'failed:' . $this->shortError($e->getMessage());
            }

            $isOk = in_array($status, ['invite_redeemed', 'already_friends'], true);
            if ($isOk) {
                $results['sent'][] = ['target' => $targetSid, 'result' => $status];
                $this->log("addFriends {$login} → {$targetSid}: {$status}");
                if ($onProgress) $onProgress("  ✓ {$targetSid}: {$status}");
            } else {
                $results['errors'][] = ['target' => $targetSid, 'error' => $status];
                $this->log("addFriends {$login} → {$targetSid}: {$status}");
                if ($onProgress) $onProgress("  ✕ {$targetSid}: {$status}");
            }

            // Пауза между парами — короткая, поскольку invites/ajaxcreate
            // и /user/<short>/<token>/ слабо лимитятся (это не AddFriendAjax).
            usleep(random_int(800_000, 1_500_000));
        }

        return $results;
    }

    /**
     * Один полный шаг A→B: A создаёт одноразовый invite_token, B логинится
     * и переходит по https://s.team/p/<short>/<token>; Steam серверно
     * регистрирует обоюдную дружбу. Возвращает финальный статус.
     */
    private function addOnePair(array $A, string $targetSid, array $byId, string $logLogin): string
    {
        if (!isset($byId[$targetSid])) {
            return 'no_account_for_target';
        }

        // 1. mint
        $token = '';
        try {
            $token = $this->apiCreateInviteToken($A['session'], $A['proxy']);
        } catch (Throwable $e) {
            $msg = $this->shortError($e->getMessage());
            $this->log("addFriends {$logLogin} → {$targetSid}: create_invite_failed: {$msg}");
            return 'create_invite_failed:' . $msg;
        }

        // 2. login B (с кэшированием)
        try {
            $B = $this->ensureAccountSession($byId[$targetSid]);
        } catch (Throwable $e) {
            return 'b_login_failed:' . $this->shortError($e->getMessage());
        }

        // 3. redeem
        return $this->apiRedeemQuickInvite(
            $B['session'], $A['short_url'], $token, $A['session']['steamid'], $B['proxy']
        );
    }

    /** Cookie-заголовок для steamcommunity.com. */
    private function communityCookieHeader(array $session): string
    {
        // steam_login_secure уже хранится URL-encoded (как поставил Set-Cookie от Steam).
        return 'sessionid=' . $session['sessionid']
             . '; steamLoginSecure=' . $session['steam_login_secure'];
    }

    /**
     * GET https://steamcommunity.com/my/ → парсим data-userinfo → short_url.
     * short_url имеет вид "https://s.team/p/<encoded>" — персональный префикс
     * quick-invite ссылки. Возвращает '' если не получилось (тогда логически
     * cookie-сессия не валидна для community).
     */
    private function apiFetchOwnShortUrl(array $session, ?array $proxy): string
    {
        $resp = $this->httpRequest('GET', 'https://steamcommunity.com/my/', null, $proxy, [
            'Accept: text/html,*/*',
            'Cookie: ' . $this->communityCookieHeader($session),
        ]);
        // /my/ редиректит на /profiles/<id>/, нам важен любой ответ с data-userinfo
        if ($resp['code'] >= 300 && $resp['code'] < 400 && !empty($resp['headers']['location'])) {
            $loc = $resp['headers']['location'];
            if ($loc[0] === '/') $loc = 'https://steamcommunity.com' . $loc;
            $resp = $this->httpRequest('GET', $loc, null, $proxy, [
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
     *   resp: {"success":1,"data":{"invite":{"invite_token":"<секрет>"}}}
     */
    private function apiCreateInviteToken(array $session, ?array $proxy): string
    {
        $body = http_build_query([
            'sessionid'    => $session['sessionid'],
            'steamid_user' => $session['steamid'],
            'duration'     => '2592000',
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
            throw new RuntimeException('access_denied (HTTP ' . $resp['code'] . ')');
        }
        if ($resp['code'] === 429) {
            throw new RuntimeException('rate_limited (HTTP 429)');
        }

        $data = json_decode($resp['body'] ?: '', true);
        if (!is_array($data)) {
            // Если cookie невалидна — возвращается HTML login-страницы.
            throw new RuntimeException('non-JSON (HTTP ' . $resp['code'] . ')');
        }
        $tok = $data['data']['invite']['invite_token']
            ?? $data['invite']['invite_token']
            ?? '';
        if (!is_string($tok) || $tok === '') {
            $err = (string)($data['error'] ?? $data['msg'] ?? 'no invite_token');
            throw new RuntimeException($err);
        }
        return $tok;
    }

    /**
     * GET <short_url>/<invite_token>  (== https://s.team/p/<short>/<token>)
     * под cookie-сессией B. s.team редиректит на /user/<short>/<token>/,
     * Steam серверно регистрирует дружбу A↔B (одноразово), затем редиректит
     * обычно на /profiles/<A>/ или /id/<A_vanity>/.
     *
     * Различаем итог по финальному URL после всех редиректов:
     *   /profiles/<A>/ или /id/<A_vanity>/  → invite_redeemed
     *   /login/                              → access_denied
     *   /user/.../ + body «expired/invalid» → invite_expired / invalid_invite
     *   прочее                                → community_error=redeem_unknown
     */
    private function apiRedeemQuickInvite(
        array $bSession, string $aShortUrl, string $token, string $aSteamId, ?array $proxy
    ): string {
        if ($aShortUrl === '' || $token === '') return 'invalid_invite';
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

        if (str_contains($finalUrl, '/login/')) return 'access_denied';

        if (preg_match('#/profiles/' . preg_quote($aSteamId, '#') . '/?#', $finalUrl)) {
            return 'invite_redeemed';
        }
        if (preg_match('#/id/[^/]+/?$#', $finalUrl)) {
            return 'invite_redeemed';
        }

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
     * Список друзей A через access_token A.
     * Возвращает map sid → true.
     */
    private function fetchFriendSetByToken(string $accessToken): array
    {
        $url = 'https://api.steampowered.com/IFriendsListService/GetFriendsList/v1/?'
             . http_build_query(['access_token' => $accessToken]);
        $resp = $this->httpRequest('GET', $url, null, null, [
            'Accept: application/json',
        ]);
        if ($resp['code'] !== 200 || $resp['body'] === '') {
            throw new RuntimeException("GetFriendsList: HTTP {$resp['code']}");
        }
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
                    $key = strtolower(trim($k));
                    $val = trim($v);
                    if ($key === 'set-cookie') {
                        $respHeaders['set-cookie'] = isset($respHeaders['set-cookie'])
                            ? array_merge((array)$respHeaders['set-cookie'], [$val])
                            : [$val];
                    } else {
                        $respHeaders[$key] = $val;
                    }
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
