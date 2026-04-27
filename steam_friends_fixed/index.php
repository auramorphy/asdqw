<?php
declare(strict_types=1);

$projectRoot = dirname(__DIR__);
for ($dir = __DIR__, $i = 0; $i < 6; $i++, $dir = dirname($dir)) {
    $candidate = dirname($dir);
    if (file_exists($candidate . '/config.php') && (file_exists($candidate . '/db.php') || is_dir($candidate . '/steamtopup'))) {
        $projectRoot = $candidate;
        break;
    }
}
if (file_exists($projectRoot . '/config.php')) require_once $projectRoot . '/config.php';
if (file_exists($projectRoot . '/db.php'))     require_once $projectRoot . '/db.php';
require_once __DIR__ . '/lib/SteamFriendManager.php';

$pdo = function_exists('db') ? db() : null;
if (!$pdo && defined('DB_HOST')) {
    $pdo = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4", DB_USER, DB_PASS, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
}

$manager  = new SteamFriendManager(__DIR__ . '/logs', $pdo);
$accounts = $pdo ? $manager->getAllAccounts() : [];
$active   = array_filter($accounts, fn($a) => $a['is_active'] && !empty($a['steamid64']));

// Загрузить кэш друзей
$cacheFile = __DIR__ . '/logs/friend_cache.json';
$friendCache = is_file($cacheFile) ? (json_decode(file_get_contents($cacheFile), true) ?: []) : [];
$activeSteamIds = array_column(array_values($active), 'steamid64');
$totalActive = count($active);
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Steam Friends Manager</title>
    <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#1a1d23;color:#e0e0e0;min-height:100vh;padding:20px}
        .container{max-width:1200px;margin:0 auto}
        h1{text-align:center;color:#4fc3f7;font-size:1.5em;margin-bottom:6px}
        .sub{text-align:center;color:#888;font-size:.88em;margin-bottom:18px}
        .sub a{color:#4fc3f7;text-decoration:none}
        h2{color:#4fc3f7;font-size:1.1em;margin:16px 0 10px}
        .card{background:#22262e;border-radius:10px;padding:18px;margin-bottom:16px;border:1px solid #333}
        .info-box{background:#0d2137;border-color:#1565c0}
        .btn{padding:8px 18px;border:none;border-radius:6px;font-size:.9em;cursor:pointer;font-weight:600;display:inline-flex;align-items:center;gap:6px;transition:all .15s}
        .btn:disabled{opacity:.4;cursor:not-allowed}
        .btn-primary{background:#1976d2;color:#fff}.btn-primary:hover:not(:disabled){background:#1565c0}
        .btn-success{background:#2e7d32;color:#fff}.btn-success:hover:not(:disabled){background:#1b5e20}
        .btn-warning{background:#e65100;color:#fff}.btn-warning:hover:not(:disabled){background:#bf360c}
        .btn-sm{padding:5px 12px;font-size:.82em}
        table{width:100%;border-collapse:collapse}
        th{background:#2a2e36;color:#4fc3f7;font-weight:600;font-size:.78em;padding:6px 8px;text-align:left;border-bottom:2px solid #444}
        td{padding:5px 8px;border-bottom:1px solid #333;font-size:.84em;vertical-align:middle}
        tr:hover td{background:#282c34}
        .tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.78em;font-weight:600}
        .tag-a{background:#1b5e20;color:#a5d6a7}.tag-i{background:#4a0000;color:#ef9a9a}
        .tag-w{background:#4a3800;color:#ffd54f}
        code{background:#2a2e36;padding:1px 5px;border-radius:3px;color:#4fc3f7;font-size:.86em}
        .chk{width:16px;height:16px;accent-color:#4fc3f7;cursor:pointer}

        .friend-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.78em;font-weight:700;min-width:42px;text-align:center}
        .fb-full{background:#1b5e20;color:#a5d6a7}
        .fb-partial{background:#4a3800;color:#ffd54f}
        .fb-none{background:#333;color:#888}
        .fb-loading{background:#333;color:#666;animation:pulse 1s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

        #log-container{display:none}
        #log{background:#0d1117;border:1px solid #333;border-radius:8px;padding:12px;max-height:400px;overflow-y:auto;font-family:'Cascadia Code','Fira Code',monospace;font-size:.82em;line-height:1.6}
        .line{padding:1px 0;white-space:pre-wrap;word-break:break-all}
        .l-ok{color:#a5d6a7}.l-err{color:#ef9a9a}.l-info{color:#90caf9}.l-warn{color:#ffd54f}.l-dim{color:#666}

        .progress-wrap{background:#2a2e36;border-radius:6px;height:26px;overflow:hidden;margin:10px 0}
        .progress-bar{background:linear-gradient(90deg,#1565c0,#42a5f5);height:100%;border-radius:6px;transition:width .3s;display:flex;align-items:center;justify-content:center;font-size:.78em;font-weight:700;color:#fff;min-width:32px}

        .stats{display:flex;gap:16px;margin:10px 0;flex-wrap:wrap}
        .stat{background:#2a2e36;padding:10px 16px;border-radius:8px;text-align:center;min-width:100px}
        .stat-num{font-size:1.6em;font-weight:700;color:#4fc3f7}
        .stat-label{font-size:.76em;color:#888;margin-top:2px}
        .stat-ok .stat-num{color:#a5d6a7}.stat-err .stat-num{color:#ef9a9a}

        .actions-bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}
        .spacer{flex:1}

        .quick-link-cell{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
        .quick-link{color:#4fc3f7;text-decoration:none;font-size:.82em;font-family:'Cascadia Code','Fira Code',monospace}
        .quick-link:hover{text-decoration:underline}
        .btn-copy{background:#2a2e36;color:#4fc3f7;border:1px solid #444;border-radius:4px;padding:2px 6px;cursor:pointer;font-size:.85em;line-height:1;transition:all .12s}
        .btn-copy:hover{background:#37424d;border-color:#4fc3f7}
        .btn-copy.copied{background:#1b5e20;border-color:#1b5e20;color:#fff}
        #toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1b5e20;color:#fff;padding:10px 18px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,.4);font-size:.9em;opacity:0;pointer-events:none;transition:opacity .2s;z-index:1000}
        #toast.show{opacity:1}
    </style>
</head>
<body>
<div class="container">
    <h1>🤝 Steam Friends Manager</h1>
    <p class="sub">
        Добавление аккаунтов-чекеров в друзья друг к другу
        <br><a href="../test/steam_gift_region_checker/admin_checkers.php">← Управление аккаунтами</a>
    </p>

    <div class="card info-box">
        <p style="font-size:.86em;color:#90caf9">
            <strong>Как это работает:</strong> Для каждого аккаунта система логинится через Steam,
            отправляет заявки в друзья всем остальным и принимает входящие.
            <br>
            <strong>Быстрая ссылка:</strong> в столбце «Быстрая ссылка» — прямой URL вида
            <code>steamcommunity.com/profiles/&lt;steamid64&gt;/friends/add</code>.
            Открой её в браузере под любым своим Steam-аккаунтом — получишь кнопку «Добавить в друзья»
            на нужного чекера. Кнопка <code>📋</code> копирует одну ссылку, кнопка
            <code>🔗 Скопировать все ссылки</code> — все сразу.
            <br>
            <strong>Требования:</strong>
            • Заполнен <code>steamid64</code> и <code>пароль</code>
            • Без Steam Guard / 2FA (только для авто-добавления)
        </p>
    </div>

    <div class="stats">
        <div class="stat">
            <div class="stat-num"><?=count($accounts)?></div>
            <div class="stat-label">Всего</div>
        </div>
        <div class="stat stat-ok">
            <div class="stat-num"><?=$totalActive?></div>
            <div class="stat-label">Готовы</div>
        </div>
        <div class="stat">
            <div class="stat-num"><?=$totalActive > 1 ? (int)($totalActive * ($totalActive - 1) / 2) : 0?></div>
            <div class="stat-label">Пар</div>
        </div>
    </div>

    <div class="card">
        <h2>Аккаунты</h2>

        <div class="actions-bar">
            <label style="font-size:.84em;color:#888;cursor:pointer">
                <input type="checkbox" id="select-all" class="chk" checked> Все
            </label>
            <div class="spacer"></div>
            <button class="btn btn-primary btn-sm" onclick="checkAllFriends()" id="btn-check">
                🔍 Проверить друзей
            </button>
            <button class="btn btn-primary btn-sm" onclick="copyAllQuickLinks()" id="btn-copy-all" title="Скопировать ссылки /friends/add для всех активных аккаунтов">
                🔗 Скопировать все ссылки
            </button>
            <button class="btn btn-success" onclick="startAddFriends(false)" id="btn-start">
                ➕ Добавить всех в друзья
            </button>
            <button class="btn btn-warning btn-sm" onclick="startAddFriends(true)" id="btn-selected">
                ➕ Только выбранные
            </button>
        </div>

        <?php if(empty($accounts)):?>
            <p style="color:#888;margin:10px 0">Нет аккаунтов.</p>
        <?php else:?>
        <table>
            <thead><tr>
                <th style="width:30px"></th>
                <th>ID</th><th>Регион</th><th>Логин</th><th>SteamID64</th><th>Друзья</th><th>Быстрая ссылка</th><th>Статус</th>
            </tr></thead>
            <tbody>
            <?php foreach($accounts as $acc):
                $hasSid = !empty($acc['steamid64']);
                $ready  = $acc['is_active'] && $hasSid;
                $sid    = $acc['steamid64'] ?? '';
                $quickLink = $hasSid ? "https://steamcommunity.com/profiles/{$sid}/friends/add" : '';

                // Из кэша
                $cached = $friendCache[$sid] ?? null;
                $friendCount = 0;
                if ($cached && !empty($cached['friends'])) {
                    // Считаем сколько из наших активных аккаунтов в друзьях
                    $friendCount = count(array_intersect($cached['friends'], $activeSteamIds));
                }
                $maxFriends = max(0, $totalActive - 1);
            ?>
                <tr data-id="<?=$acc['id']?>" data-sid="<?=htmlspecialchars($sid)?>" data-ready="<?=$ready?1:0?>">
                    <td><input type="checkbox" class="chk acc-chk" value="<?=$acc['id']?>" data-sid="<?=htmlspecialchars($sid)?>" <?=$ready?'checked':''?> <?=$ready?'':'disabled'?>></td>
                    <td><?=$acc['id']?></td>
                    <td><strong><?=htmlspecialchars($acc['region'])?></strong></td>
                    <td><code><?=htmlspecialchars($acc['login'])?></code></td>
                    <td style="font-size:.78em"><?php
                        echo $hasSid ? '<code>'.htmlspecialchars($sid).'</code>' : '<span style="color:#e57373">нет</span>';
                    ?></td>
                    <td>
                        <span class="friend-badge <?php
                            if (!$cached || !$hasSid) echo 'fb-none';
                            elseif ($friendCount >= $maxFriends) echo 'fb-full';
                            else echo 'fb-partial';
                        ?>" id="fb-<?=$acc['id']?>">
                            <?php
                            if (!$hasSid) echo '—';
                            elseif (!$cached) echo '?/?';
                            else echo $friendCount . '/' . $maxFriends;
                            ?>
                        </span>
                    </td>
                    <td>
                        <?php if ($hasSid): ?>
                            <span class="quick-link-cell">
                                <a class="quick-link" href="<?=htmlspecialchars($quickLink)?>" target="_blank" rel="noopener" title="<?=htmlspecialchars($quickLink)?>">/friends/add ↗</a>
                                <button type="button" class="btn-copy" onclick="copyQuickLink(this, '<?=htmlspecialchars($quickLink, ENT_QUOTES)?>')" title="Скопировать ссылку">📋</button>
                            </span>
                        <?php else: ?>
                            <span style="color:#666">—</span>
                        <?php endif; ?>
                    </td>
                    <td><?php
                        if ($ready) echo '<span class="tag tag-a">OK</span>';
                        elseif (!$acc['is_active']) echo '<span class="tag tag-i">OFF</span>';
                        else echo '<span class="tag tag-w">⚠</span>';
                    ?></td>
                </tr>
            <?php endforeach;?>
            </tbody>
        </table>
        <?php endif;?>
    </div>

    <!-- Progress / Log -->
    <div class="card" id="log-container">
        <h2 id="log-title">Прогресс</h2>
        <div class="progress-wrap"><div class="progress-bar" id="pbar" style="width:0%">0%</div></div>
        <div id="log"></div>
    </div>
</div>

<div id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

// Все steamid64 активных аккаунтов
const ALL_STEAM_IDS = <?=json_encode(array_values($activeSteamIds))?>;
const TOTAL_ACTIVE = <?=$totalActive?>;

// ===== Быстрые ссылки на добавление в друзья =====
function showToast(text, ok) {
    const t = $('#toast');
    t.textContent = text;
    t.style.background = ok === false ? '#b71c1c' : '#1b5e20';
    t.classList.add('show');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => t.classList.remove('show'), 1800);
}

async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch (e) { /* fallback ниже */ }
    // Fallback для http и старых браузеров
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    return ok;
}

async function copyQuickLink(btn, link) {
    const ok = await copyToClipboard(link);
    if (ok) {
        const orig = btn.textContent;
        btn.classList.add('copied');
        btn.textContent = '✓';
        setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1200);
        showToast('Ссылка скопирована');
    } else {
        showToast('Не удалось скопировать', false);
    }
}

async function copyAllQuickLinks() {
    const links = $$('tr[data-sid]')
        .filter(tr => tr.dataset.sid)
        .map(tr => 'https://steamcommunity.com/profiles/' + tr.dataset.sid + '/friends/add');
    if (!links.length) { showToast('Нет аккаунтов с steamid64', false); return; }
    const ok = await copyToClipboard(links.join('\n'));
    showToast(ok ? ('Скопировано ' + links.length + ' ссылок') : 'Не удалось скопировать', ok);
}

$('#select-all').addEventListener('change', function() {
    $$('.acc-chk:not(:disabled)').forEach(c => c.checked = this.checked);
});

function getSelectedAccounts() {
    return $$('.acc-chk:checked').map(c => ({
        id: parseInt(c.value),
        sid: c.dataset.sid,
    }));
}

function setButtons(disabled) {
    $$('.btn').forEach(b => b.disabled = disabled);
}

function log(text, cls) {
    const el = document.createElement('div');
    el.className = 'line' + (cls ? ' l-' + cls : '');
    el.textContent = text;
    $('#log').appendChild(el);
    $('#log').scrollTop = 999999;
}

function setProgress(pct) {
    const bar = $('#pbar');
    bar.style.width = Math.max(pct, 1) + '%';
    bar.textContent = Math.round(pct) + '%';
}

function updateBadge(accId, count, max, cls) {
    const el = $('#fb-' + accId);
    if (!el) return;
    el.textContent = count + '/' + max;
    el.className = 'friend-badge ' + cls;
}

// ===== POST helper =====
function apiPost(action, params) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'api.php', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.timeout = 120000; // 2 мин на аккаунт
        xhr.onload = function() {
            try {
                resolve(JSON.parse(xhr.responseText));
            } catch(e) {
                reject(new Error('Невалидный ответ: ' + xhr.responseText.substring(0, 200)));
            }
        };
        xhr.onerror = () => reject(new Error('Нет соединения'));
        xhr.ontimeout = () => reject(new Error('Таймаут (2 мин)'));

        let body = 'action=' + encodeURIComponent(action);
        for (const [k, v] of Object.entries(params)) {
            if (Array.isArray(v)) {
                v.forEach(item => body += '&' + encodeURIComponent(k + '[]') + '=' + encodeURIComponent(item));
            } else {
                body += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(v);
            }
        }
        xhr.send(body);
    });
}

// ===== ДОБАВИТЬ В ДРУЗЬЯ =====
async function startAddFriends(selectedOnly) {
    const accs = selectedOnly ? getSelectedAccounts() : getSelectedAccounts();
    if (accs.length < 2) {
        alert('Выберите минимум 2 аккаунта');
        return;
    }
    if (!confirm(selectedOnly
        ? 'Добавить ' + accs.length + ' выбранных в друзья?'
        : 'Добавить все ' + accs.length + ' аккаунтов в друзья?'
    )) return;

    setButtons(true);
    $('#log-container').style.display = 'block';
    $('#log-title').textContent = 'Добавление в друзья';
    $('#log').innerHTML = '';
    setProgress(0);

    const targetIds = accs.map(a => a.sid);
    let totalSent = 0, totalErr = 0;

    for (let i = 0; i < accs.length; i++) {
        const acc = accs[i];
        const pct = (i / accs.length) * 100;
        setProgress(pct);

        log('');
        log('[' + (i+1) + '/' + accs.length + '] Аккаунт #' + acc.id + ' — логин...', 'info');

        try {
            const resp = await apiPost('add_one', {
                account_id: acc.id,
                target_ids: targetIds,
            });

            if (resp.ok) {
                totalSent += resp.sent || 0;
                totalErr  += resp.errors || 0;

                // Лог от сервера
                if (resp.log) resp.log.forEach(m => {
                    let cls = 'dim';
                    if (m.includes('✅') || m.includes('залогинен')) cls = 'ok';
                    else if (m.includes('✕') || m.includes('failed') || m.includes('error')) cls = 'err';
                    else if (m.includes('✓') || m.includes('sent') || m.includes('accept')) cls = 'ok';
                    log(m, cls);
                });

                const errN = resp.errors || 0;
                if (errN > 0) {
                    log('⚠ ' + resp.login + ': ' + resp.sent + ' ok, ' + errN + ' ошибок', 'warn');
                    if (resp.error_details) resp.error_details.forEach(e => log('  └ ' + e, 'err'));
                } else {
                    log('✅ ' + resp.login + ': ' + resp.sent + ' отправлено', 'ok');
                }
            } else {
                totalErr++;
                log('❌ #' + acc.id + ': ' + (resp.error || 'unknown'), 'err');
            }
        } catch(e) {
            totalErr++;
            log('❌ #' + acc.id + ': ' + e.message, 'err');
        }

        // Пауза между аккаунтами
        if (i < accs.length - 1) {
            const delay = 2 + Math.random() * 3;
            log('⏳ Пауза ' + delay.toFixed(0) + ' сек...', 'dim');
            await new Promise(r => setTimeout(r, delay * 1000));
        }
    }

    setProgress(100);
    log('');
    log('🎉 Готово! Отправлено: ' + totalSent + ', ошибок: ' + totalErr,
        totalErr === 0 ? 'ok' : 'warn');
    setButtons(false);
}

// ===== ПРОВЕРИТЬ ДРУЗЕЙ =====
async function checkAllFriends() {
    const accs = getSelectedAccounts();
    if (accs.length === 0) {
        alert('Выберите аккаунты для проверки');
        return;
    }

    setButtons(true);
    $('#log-container').style.display = 'block';
    $('#log-title').textContent = 'Проверка друзей';
    $('#log').innerHTML = '';
    setProgress(0);

    // Пометить все как "loading"
    accs.forEach(a => {
        const el = $('#fb-' + a.id);
        if (el) { el.textContent = '...'; el.className = 'friend-badge fb-loading'; }
    });

    for (let i = 0; i < accs.length; i++) {
        const acc = accs[i];
        setProgress((i / accs.length) * 100);
        log('[' + (i+1) + '/' + accs.length + '] Проверка #' + acc.id + '...', 'info');

        try {
            const resp = await apiPost('check_one', {
                account_id: acc.id,
                all_steam_ids: ALL_STEAM_IDS,
            });

            if (resp.ok) {
                const cnt = resp.count || 0;
                const max = Math.max(0, TOTAL_ACTIVE - 1);
                const cls = cnt >= max ? 'fb-full' : (cnt > 0 ? 'fb-partial' : 'fb-none');
                updateBadge(acc.id, cnt, max, cls);
                log('✅ ' + resp.login + ': ' + cnt + '/' + max + ' друзей', cnt >= max ? 'ok' : 'warn');
            } else {
                log('❌ ' + (resp.login || '#' + acc.id) + ': ' + (resp.error || '?'), 'err');
                updateBadge(acc.id, '?', Math.max(0, TOTAL_ACTIVE-1), 'fb-none');
            }
        } catch(e) {
            log('❌ #' + acc.id + ': ' + e.message, 'err');
            updateBadge(acc.id, '?', Math.max(0, TOTAL_ACTIVE-1), 'fb-none');
        }

        if (i < accs.length - 1) {
            await new Promise(r => setTimeout(r, 2000 + Math.random() * 2000));
        }
    }

    setProgress(100);
    log('');
    log('Проверка завершена', 'ok');
    setButtons(false);
}
</script>
</body>
</html>
