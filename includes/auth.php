<?php
require_once __DIR__.'/../config/config.php';
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/validator.php';

// ── Session ──────────────────────────────────────────────────
function startSecureSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_name(SESSION_NAME);
        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
        if (!isset($_SESSION['_init'])) {
            session_regenerate_id(true);
            $_SESSION['_init'] = true;
        }
    }
}

// ── CSRF ─────────────────────────────────────────────────────
function generateCsrfToken(): string {
    if (empty($_SESSION[CSRF_TOKEN_NAME]))
        $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
    return $_SESSION[CSRF_TOKEN_NAME];
}
function verifyCsrfToken(string $t): bool {
    return isset($_SESSION[CSRF_TOKEN_NAME]) && hash_equals($_SESSION[CSRF_TOKEN_NAME], $t);
}
function csrfField(): string {
    return '<input type="hidden" name="'.CSRF_TOKEN_NAME.'" value="'.generateCsrfToken().'">';
}

// ── IP / Rate Limiting ────────────────────────────────────────
function getClientIp(): string {
    foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $k) {
        if (!empty($_SERVER[$k])) {
            $ip = trim(explode(',', $_SERVER[$k])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return '0.0.0.0';
}
function isRateLimited(): bool {
    $pdo  = getDB(); $ip = getClientIp();
    $cut  = date('Y-m-d H:i:s', time() - LOCKOUT_MINUTES * 60);
    $s    = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address=? AND attempted_at>?");
    $s->execute([$ip, $cut]);
    return (int)$s->fetchColumn() >= MAX_LOGIN_ATTEMPTS;
}
function getRemainingLockout(): int {
    $pdo  = getDB(); $ip = getClientIp();
    $cut  = date('Y-m-d H:i:s', time() - LOCKOUT_MINUTES * 60);
    $s    = $pdo->prepare("SELECT MIN(attempted_at) FROM login_attempts WHERE ip_address=? AND attempted_at>?");
    $s->execute([$ip, $cut]);
    $first = $s->fetchColumn();
    if (!$first) return 0;
    return max(0, LOCKOUT_MINUTES * 60 - (time() - strtotime($first)));
}
function recordLoginAttempt(string $email = ''): void {
    $pdo = getDB();
    $pdo->prepare("INSERT INTO login_attempts (ip_address, email) VALUES (?,?)")->execute([getClientIp(), $email ?: null]);
    $pdo->exec("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
}
function clearLoginAttempts(string $email = ''): void {
    $pdo = getDB();
    $pdo->prepare("DELETE FROM login_attempts WHERE ip_address=? OR email=?")->execute([getClientIp(), $email]);
}

// ── Auth checks ───────────────────────────────────────────────
function isLoggedIn(): bool {
    return !empty($_SESSION['logged_in'])
        && !empty($_SESSION['user_id'])
        && (time() - ($_SESSION['login_time'] ?? 0)) < SESSION_LIFETIME;
}
function requireLogin(): void {
    if (!isLoggedIn()) {
        header('Location: '.APP_URL.'/index.php?redirect='.urlencode($_SERVER['REQUEST_URI']));
        exit;
    }
}
function redirectIfLoggedIn(): void {
    if (isLoggedIn()) { header('Location: '.APP_URL.'/home.php'); exit; }
}

// ── Register ──────────────────────────────────────────────────
function registerUser(array $data): array {
    $v = validate($data)
        ->required('name',     'Full Name')
        ->alpha('name',        'Full Name')
        ->minLength('name',    'Full Name', 2)
        ->maxLength('name',    'Full Name', 100)
        ->required('email',    'Email Address')
        ->email('email')
        ->uniqueEmail('email')
        ->required('password', 'Password')
        ->password('password')
        ->matches('confirm_password', 'password', 'Confirm Password')
        ->accepted('terms',    'Terms & Conditions');

    if ($v->fails()) return ['success' => false, 'errors' => $v->errors()];

    $pdo    = getDB();
    $colors = ['#6c63ff','#e84393','#00b4d8','#06d6a0','#f59e0b','#ef4444'];
    $color  = $colors[array_rand($colors)];
    $hash   = password_hash($data['password'], PASSWORD_BCRYPT, ['cost' => 12]);

    $pdo->prepare("INSERT INTO users (name, email, password, avatar_color, is_verified) VALUES (?,?,?,?,0)")
        ->execute([sanitize($data['name']), strtolower(trim($data['email'])), $hash, $color]);

    $userId = (int)$pdo->lastInsertId();

    // Send email verification OTP
    $otp = generateOtp($data['email'], 'verify_email');
    sendOtpEmail($data['email'], $otp, 'verify_email', sanitize($data['name']));

    // Store pending verification in session
    $_SESSION['pending_verify_email'] = strtolower(trim($data['email']));

    return ['success' => true, 'user_id' => $userId];
}

// ── Login ─────────────────────────────────────────────────────
function loginUser(string $email, string $password): array {
    // Validate input first
    $v = validate(['email' => $email, 'password' => $password])
        ->required('email',    'Email Address')
        ->email('email')
        ->required('password', 'Password');

    if ($v->fails()) return ['success' => false, 'errors' => $v->errors()];

    // Rate limiting
    if (isRateLimited()) {
        $remaining = getRemainingLockout();
        $mins = ceil($remaining / 60);
        return ['success' => false, 'errors' => ['email' => "Too many failed attempts. Try again in $mins minute(s)."]];
    }

    $pdo   = getDB();
    $email = strtolower(trim($email));
    $s     = $pdo->prepare("SELECT * FROM users WHERE email=? AND is_active=1 LIMIT 1");
    $s->execute([$email]);
    $user  = $s->fetch();

    if (!$user || !password_verify($password, $user['password'])) {
        recordLoginAttempt($email);
        // How many attempts left
        $cut  = date('Y-m-d H:i:s', time() - LOCKOUT_MINUTES * 60);
        $cnt  = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address=? AND attempted_at>?");
        $cnt->execute([getClientIp(), $cut]);
        $used = (int)$cnt->fetchColumn();
        $left = max(0, MAX_LOGIN_ATTEMPTS - $used);
        $msg  = $left > 0
            ? "Invalid email or password. $left attempt(s) remaining."
            : "Account temporarily locked. Try again in ".LOCKOUT_MINUTES." minutes.";
        return ['success' => false, 'errors' => ['password' => $msg]];
    }

    // Rehash if needed
    if (password_needs_rehash($user['password'], PASSWORD_BCRYPT, ['cost' => 12])) {
        $pdo->prepare("UPDATE users SET password=? WHERE id=?")
            ->execute([password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]), $user['id']]);
    }

    clearLoginAttempts($email);
    session_regenerate_id(true);

    $_SESSION['user_id']    = $user['id'];
    $_SESSION['user_name']  = $user['name'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['user_color'] = $user['avatar_color'];
    $_SESSION['verified']   = (bool)$user['is_verified'];
    $_SESSION['logged_in']  = true;
    $_SESSION['login_time'] = time();

    $pdo->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]);
    $pdo->prepare("INSERT INTO sessions (user_id, ip_address, user_agent) VALUES (?,?,?)")
        ->execute([$user['id'], getClientIp(), substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)]);

    return ['success' => true];
}

// ── Logout ────────────────────────────────────────────────────
function logoutUser(): void {
    startSecureSession();
    $_SESSION = [];
    session_destroy();
    setcookie(SESSION_NAME, '', time() - 3600, '/', '', isset($_SERVER['HTTPS']), true);
    header('Location: '.APP_URL.'/index.php?msg=logged_out');
    exit;
}

// ── OTP ───────────────────────────────────────────────────────
function generateOtp(string $email, string $type): string {
    $pdo  = getDB();
    $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $exp  = date('Y-m-d H:i:s', time() + OTP_EXPIRY_MINUTES * 60);

    // Invalidate old OTPs of same type
    $pdo->prepare("UPDATE otp_codes SET used=1 WHERE email=? AND type=? AND used=0")
        ->execute([$email, $type]);

    $pdo->prepare("INSERT INTO otp_codes (email, code, type, expires_at) VALUES (?,?,?,?)")
        ->execute([$email, $code, $type, $exp]);

    return $code;
}

function verifyOtp(string $email, string $code, string $type): array {
    $v = validate(['otp' => $code])->otp('otp');
    if ($v->fails()) return ['success' => false, 'errors' => $v->errors()];

    $pdo = getDB();
    $s   = $pdo->prepare("SELECT * FROM otp_codes WHERE email=? AND type=? AND used=0 AND expires_at>NOW() ORDER BY id DESC LIMIT 1");
    $s->execute([$email, $type]);
    $row = $s->fetch();

    if (!$row) return ['success' => false, 'errors' => ['otp' => 'OTP has expired. Please request a new one.']];

    // Increment attempt count
    $pdo->prepare("UPDATE otp_codes SET attempts=attempts+1 WHERE id=?")->execute([$row['id']]);

    if ($row['attempts'] >= OTP_MAX_ATTEMPTS) {
        $pdo->prepare("UPDATE otp_codes SET used=1 WHERE id=?")->execute([$row['id']]);
        return ['success' => false, 'errors' => ['otp' => 'Too many wrong attempts. Please request a new OTP.']];
    }

    if (!hash_equals($row['code'], $code)) {
        $left = OTP_MAX_ATTEMPTS - $row['attempts'] - 1;
        return ['success' => false, 'errors' => ['otp' => "Incorrect OTP. $left attempt(s) remaining."]];
    }

    // Mark used
    $pdo->prepare("UPDATE otp_codes SET used=1 WHERE id=?")->execute([$row['id']]);
    return ['success' => true];
}

function canResendOtp(string $email, string $type): bool {
    $pdo = getDB();
    $s   = $pdo->prepare("SELECT created_at FROM otp_codes WHERE email=? AND type=? ORDER BY id DESC LIMIT 1");
    $s->execute([$email, $type]);
    $row = $s->fetch();
    if (!$row) return true;
    return (time() - strtotime($row['created_at'])) >= OTP_RESEND_COOLDOWN;
}

function getResendCooldown(string $email, string $type): int {
    $pdo = getDB();
    $s   = $pdo->prepare("SELECT created_at FROM otp_codes WHERE email=? AND type=? ORDER BY id DESC LIMIT 1");
    $s->execute([$email, $type]);
    $row = $s->fetch();
    if (!$row) return 0;
    return max(0, OTP_RESEND_COOLDOWN - (time() - strtotime($row['created_at'])));
}

// ── Send OTP Email ────────────────────────────────────────────
function sendOtpEmail(string $toEmail, string $otp, string $type, string $toName = ''): bool {
    $subject = match($type) {
        'verify_email'   => APP_NAME.' — Verify Your Email',
        'reset_password' => APP_NAME.' — Password Reset OTP',
        default          => APP_NAME.' — Your OTP Code',
    };

    $action = match($type) {
        'verify_email'   => 'verify your email address',
        'reset_password' => 'reset your password',
        default          => 'complete your request',
    };

    $greeting = $toName ? "Hi $toName," : "Hello,";

    $html = <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:'Segoe UI',Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 0">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#111;border:1px solid #222;border-radius:16px;overflow:hidden;max-width:520px;width:100%">
        <!-- Header -->
        <tr><td style="background:#6c63ff;padding:28px 32px;text-align:center">
          <div style="font-family:'Segoe UI',Arial,sans-serif;font-size:24px;font-weight:700;color:#fff;letter-spacing:1px">🔐 {APP_NAME}</div>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:36px 32px">
          <p style="color:#ccc;font-size:15px;margin:0 0 10px">$greeting</p>
          <p style="color:#888;font-size:14px;margin:0 0 28px">Use the OTP below to $action. This code expires in <strong style="color:#fff">{OTP_EXPIRY_MINUTES} minutes</strong>.</p>
          <!-- OTP Box -->
          <div style="background:#1a1a1a;border:2px dashed #6c63ff;border-radius:12px;padding:24px;text-align:center;margin:0 0 28px">
            <div style="font-size:42px;font-weight:700;letter-spacing:12px;color:#6c63ff;font-family:'Courier New',monospace">$otp</div>
            <div style="font-size:12px;color:#555;margin-top:8px">Enter this code on the website</div>
          </div>
          <p style="color:#555;font-size:12px;margin:0 0 6px">⏱ Expires in {OTP_EXPIRY_MINUTES} minutes</p>
          <p style="color:#555;font-size:12px;margin:0 0 6px">🔒 Never share this code with anyone</p>
          <p style="color:#555;font-size:12px;margin:0">❌ If you didn't request this, ignore this email</p>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:18px 32px;border-top:1px solid #1e1e1e;text-align:center">
          <p style="color:#333;font-size:11px;margin:0">© {APP_NAME} · Automated email, do not reply</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
HTML;

    $html = str_replace(['{APP_NAME}', '{OTP_EXPIRY_MINUTES}'], [APP_NAME, OTP_EXPIRY_MINUTES], $html);

    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: ".MAIL_FROM_NAME." <".MAIL_FROM.">\r\n";
    $headers .= "Reply-To: ".MAIL_FROM."\r\n";
    $headers .= "X-Mailer: PHP/".phpversion()."\r\n";

    $sent = @mail($toEmail, $subject, $html, $headers);

    // In DEBUG mode, store OTP in session so we can display it (dev only)
    if (DEBUG_MODE) {
        $_SESSION['debug_otp']       = $otp;
        $_SESSION['debug_otp_email'] = $toEmail;
        $_SESSION['debug_otp_type']  = $type;
    }

    return $sent;
}

// ── Password Reset ────────────────────────────────────────────
function requestPasswordReset(string $email): array {
    $v = validate(['email' => $email])
        ->required('email', 'Email Address')
        ->email('email');

    if ($v->fails()) return ['success' => false, 'errors' => $v->errors()];

    $email = strtolower(trim($email));
    $pdo   = getDB();
    $s     = $pdo->prepare("SELECT * FROM users WHERE email=? AND is_active=1 LIMIT 1");
    $s->execute([$email]);
    $user  = $s->fetch();

    // Don't reveal if user exists
    if (!$user) return ['success' => true];

    if (!canResendOtp($email, 'reset_password')) {
        $wait = getResendCooldown($email, 'reset_password');
        return ['success' => false, 'errors' => ['email' => "Please wait $wait second(s) before requesting another OTP."]];
    }

    $otp = generateOtp($email, 'reset_password');
    sendOtpEmail($email, $otp, 'reset_password', $user['name']);

    $_SESSION['reset_email'] = $email;

    return ['success' => true];
}

function resetPassword(string $email, string $newPassword, string $confirmPassword): array {
    $v = validate(['password' => $newPassword, 'confirm_password' => $confirmPassword])
        ->required('password',         'New Password')
        ->password('password',         'New Password')
        ->required('confirm_password', 'Confirm Password')
        ->matches('confirm_password',  'password', 'Confirm Password');

    if ($v->fails()) return ['success' => false, 'errors' => $v->errors()];

    $pdo  = getDB();
    $hash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    $pdo->prepare("UPDATE users SET password=? WHERE email=?")->execute([$hash, $email]);

    unset($_SESSION['reset_email'], $_SESSION['reset_verified']);

    return ['success' => true];
}

// ── Helpers ───────────────────────────────────────────────────
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8'); }
function sanitize(string $s): string { return trim(strip_tags($s)); }
function old(string $field, array $data): string { return h($data[$field] ?? ''); }
function getAvatarInitials(string $name): string {
    $p = explode(' ', trim($name));
    $i = strtoupper(substr($p[0], 0, 1));
    if (isset($p[1])) $i .= strtoupper(substr($p[1], 0, 1));
    return $i;
}

// Flash messages
function setFlash(string $type, string $msg): void { $_SESSION['flash'] = ['type' => $type, 'msg' => $msg]; }
function getFlash(): ?array { if (isset($_SESSION['flash'])) { $f = $_SESSION['flash']; unset($_SESSION['flash']); return $f; } return null; }
