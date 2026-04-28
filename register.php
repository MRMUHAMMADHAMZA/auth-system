<?php
require_once __DIR__.'/config/config.php';
require_once __DIR__.'/includes/auth.php';
startSecureSession();
redirectIfLoggedIn();

$errors = []; $old = [];
$step   = $_SESSION['pending_verify_email'] ?? null ? 'verify' : 'register';

// ── Handle OTP verification ──────────────────────────────────
if ($step === 'verify' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['otp_1'])) {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors['global'] = 'Invalid request.';
    } else {
        $code   = implode('', array_map(fn($i) => preg_replace('/\D/', '', $_POST["otp_$i"] ?? ''), range(1, 6)));
        $email  = $_SESSION['pending_verify_email'] ?? '';
        $result = verifyOtp($email, $code, 'verify_email');
        if ($result['success']) {
            getDB()->prepare("UPDATE users SET is_verified=1 WHERE email=?")->execute([$email]);
            unset($_SESSION['pending_verify_email']);
            setFlash('success', '✓ Email verified! Your account is ready. Please sign in.');
            header('Location: '.APP_URL.'/index.php'); exit;
        }
        $errors = $result['errors'];
    }
}

// ── Handle Resend OTP ─────────────────────────────────────────
if (isset($_POST['resend_otp'])) {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors['global'] = 'Invalid request.';
    } else {
        $email = $_SESSION['pending_verify_email'] ?? '';
        if ($email) {
            if (!canResendOtp($email, 'verify_email')) {
                $wait = getResendCooldown($email, 'verify_email');
                $errors['otp'] = "Please wait $wait second(s) before resending.";
            } else {
                $pdo  = getDB();
                $u    = $pdo->prepare("SELECT name FROM users WHERE email=?"); $u->execute([$email]); $u=$u->fetch();
                $otp  = generateOtp($email, 'verify_email');
                sendOtpEmail($email, $otp, 'verify_email', $u['name'] ?? '');
                setFlash('success', 'A new OTP has been sent to your email.');
                header('Location: '.APP_URL.'/register.php'); exit;
            }
        }
    }
}

// ── Handle Registration ───────────────────────────────────────
if ($step === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['resend_otp'])) {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors['global'] = 'Invalid request.';
    } else {
        $old    = $_POST;
        $result = registerUser($_POST);
        if ($result['success']) {
            $step = 'verify';
        } else {
            $errors = $result['errors'];
        }
    }
}

$flash = getFlash();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= $step === 'verify' ? 'Verify Email' : 'Create Account' ?> — <?= APP_NAME ?></title>
  <link rel="stylesheet" href="<?= APP_URL ?>/assets/css/style.css">
</head>
<body>
<div class="bg-blobs">
  <div class="blob blob-1"></div><div class="blob blob-2"></div><div class="blob blob-3"></div>
</div>

<div class="auth-page">
  <div class="auth-card">

    <div class="auth-logo">
      <div class="logo-icon">🔐</div>
      <div class="logo-text"><?= APP_NAME ?></div>
    </div>

    <!-- Steps indicator -->
    <div class="steps">
      <div class="step-item <?= $step==='register'?'active':'done' ?>">
        <div class="step-dot"><?= $step==='verify'?'✓':'1' ?></div>
        <div class="step-label">Account</div>
      </div>
      <div class="step-item <?= $step==='verify'?'active':'' ?>">
        <div class="step-dot">2</div>
        <div class="step-label">Verify</div>
      </div>
    </div>

    <?php if ($flash): ?>
      <div class="alert alert--<?= h($flash['type']) ?>">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <?= h($flash['msg']) ?>
      </div>
    <?php endif; ?>

    <?php if (!empty($errors['global'])): ?>
      <div class="alert alert--error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <?= h($errors['global']) ?>
      </div>
    <?php endif; ?>

    <?php if ($step === 'verify'): ?>
    <!-- ── OTP VERIFICATION STEP ── -->
    <div class="auth-header">
      <h1>Verify your email</h1>
      <p>We sent a 6-digit code to your inbox</p>
    </div>

    <?php if (DEBUG_MODE && isset($_SESSION['debug_otp'])): ?>
    <div class="debug-box">
      <strong>🛠 DEV MODE — OTP Code:</strong>
      <div class="debug-otp"><?= h($_SESSION['debug_otp']) ?></div>
      Sent to: <?= h($_SESSION['debug_otp_email'] ?? '') ?>
    </div>
    <?php endif; ?>

    <div class="otp-info">
      <div class="otp-email">Code sent to <strong><?= h($_SESSION['pending_verify_email'] ?? '') ?></strong></div>
    </div>

    <?php if (!empty($errors['otp'])): ?>
      <div class="alert alert--error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <?= h($errors['otp']) ?>
      </div>
    <?php endif; ?>

    <form method="POST" id="otpForm">
      <?= csrfField() ?>
      <div class="otp-inputs" id="otpInputs">
        <?php for($i=1;$i<=6;$i++): ?>
          <input type="text" name="otp_<?= $i ?>" id="otp<?= $i ?>"
            maxlength="1" pattern="\d" inputmode="numeric"
            autocomplete="one-time-code"
            class="<?= !empty($errors['otp'])?'is-error':'' ?>"
            oninput="otpInput(this,<?= $i ?>)"
            onkeydown="otpKeydown(event,<?= $i ?>)"
            onpaste="otpPaste(event)">
        <?php endfor; ?>
      </div>

      <!-- Timer -->
      <div class="otp-info mt-8">
        <div class="otp-timer" id="timerWrap">
          Code expires in <span id="countdown"><?= OTP_EXPIRY_MINUTES ?>:00</span>
        </div>
        <div id="expiredMsg" style="display:none;font-size:.8rem;color:var(--danger)">Code expired. Please resend.</div>
      </div>

      <button type="submit" class="btn btn--primary mt-16" id="verifyBtn">
        <span class="btn-text">Verify Email ✓</span>
        <div class="spinner"></div>
      </button>
    </form>

    <div class="text-center mt-16">
      <form method="POST" style="display:inline">
        <?= csrfField() ?>
        <input type="hidden" name="resend_otp" value="1">
        <button type="submit" class="resend-btn" id="resendBtn">Didn't receive it? Resend OTP</button>
      </form>
    </div>

    <div class="auth-footer">
      <a href="<?= APP_URL ?>/register.php?cancel=1" onclick="return confirm('Cancel registration?')">← Use a different email</a>
    </div>

    <?php else: ?>
    <!-- ── REGISTER STEP ── -->
    <div class="auth-header">
      <h1>Create account</h1>
      <p>Fill in your details to get started</p>
    </div>

    <form method="POST" id="registerForm" novalidate>
      <?= csrfField() ?>

      <!-- Full Name -->
      <div class="form-group">
        <label for="name">Full Name <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <input type="text" id="name" name="name" placeholder="Muhammad Hamza"
            value="<?= old('name', $old) ?>"
            class="<?= !empty($errors['name']) ? 'is-error' : '' ?>"
            autocomplete="name" oninput="clearErr('name'); validateName(this)">
        </div>
        <?php if (!empty($errors['name'])): ?>
          <div class="field-error">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['name']) ?>
          </div>
        <?php endif; ?>
      </div>

      <!-- Email -->
      <div class="form-group">
        <label for="email">Email Address <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="2" y="4" width="20" height="16" rx="3"/><path d="M2 8l10 7 10-7"/></svg>
          <input type="email" id="email" name="email" placeholder="you@example.com"
            value="<?= old('email', $old) ?>"
            class="<?= !empty($errors['email']) ? 'is-error' : '' ?>"
            autocomplete="email" oninput="clearErr('email'); validateEmail(this)">
        </div>
        <?php if (!empty($errors['email'])): ?>
          <div class="field-error">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['email']) ?>
          </div>
        <?php endif; ?>
      </div>

      <!-- Password -->
      <div class="form-group">
        <label for="password">Password <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" id="password" name="password" placeholder="Min 8 chars"
            class="<?= !empty($errors['password']) ? 'is-error' : '' ?>"
            autocomplete="new-password" oninput="clearErr('password'); updateStrength(this.value)">
          <svg class="icon-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" onclick="togglePw('password',this)"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <?php if (!empty($errors['password'])): ?>
          <div class="field-error">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['password']) ?>
          </div>
        <?php endif; ?>
        <!-- Strength bars -->
        <div class="pw-strength">
          <div class="pw-bars">
            <div class="pw-bar" id="bar1"></div>
            <div class="pw-bar" id="bar2"></div>
            <div class="pw-bar" id="bar3"></div>
            <div class="pw-bar" id="bar4"></div>
          </div>
          <div class="pw-label" id="pwLabel"></div>
        </div>
        <!-- Rules -->
        <div class="pw-rules">
          <div class="pw-rule" id="rule-len"><div class="dot"></div>At least 8 characters</div>
          <div class="pw-rule" id="rule-upper"><div class="dot"></div>One uppercase letter (A-Z)</div>
          <div class="pw-rule" id="rule-lower"><div class="dot"></div>One lowercase letter (a-z)</div>
          <div class="pw-rule" id="rule-num"><div class="dot"></div>One number (0-9)</div>
          <div class="pw-rule" id="rule-special"><div class="dot"></div>One special character (@, #, ! …)</div>
        </div>
      </div>

      <!-- Confirm Password -->
      <div class="form-group">
        <label for="confirm_password">Confirm Password <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" id="confirm_password" name="confirm_password" placeholder="Repeat password"
            class="<?= !empty($errors['confirm_password']) ? 'is-error' : '' ?>"
            autocomplete="new-password" oninput="clearErr('confirm_password'); checkMatch()">
          <svg class="icon-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" onclick="togglePw('confirm_password',this)"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <?php if (!empty($errors['confirm_password'])): ?>
          <div class="field-error">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['confirm_password']) ?>
          </div>
        <?php endif; ?>
        <div class="field-success" id="matchOk" style="display:none">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>
          Passwords match
        </div>
      </div>

      <!-- Terms -->
      <div class="form-group">
        <div class="check-wrap">
          <input type="checkbox" id="terms" name="terms" value="1" <?= !empty($old['terms']) ? 'checked' : '' ?>>
          <label for="terms">I agree to the <a href="#" style="color:var(--accent)">Terms of Service</a> and <a href="#" style="color:var(--accent)">Privacy Policy</a></label>
        </div>
        <?php if (!empty($errors['terms'])): ?>
          <div class="field-error" style="margin-top:4px">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['terms']) ?>
          </div>
        <?php endif; ?>
      </div>

      <button type="submit" class="btn btn--primary" id="registerBtn">
        <span class="btn-text">Create Account →</span>
        <div class="spinner"></div>
      </button>
    </form>

    <div class="auth-footer">
      Already have an account? <a href="<?= APP_URL ?>/index.php">Sign in</a>
    </div>
    <?php endif; ?>

  </div>
</div>

<?php
if (isset($_GET['cancel'])) {
    unset($_SESSION['pending_verify_email'], $_SESSION['debug_otp']);
    header('Location: '.APP_URL.'/register.php'); exit;
}
?>

<script>
// ── Toggle Password ────────────────────────────────────────
function togglePw(id, icon) {
  const input = document.getElementById(id);
  input.type = input.type === 'password' ? 'text' : 'password';
}

// ── Clear field error ──────────────────────────────────────
function clearErr(field) {
  const input = document.querySelector(`[name="${field}"]`);
  const err   = input?.closest('.form-group')?.querySelector('.field-error');
  if (input) input.classList.remove('is-error');
  if (err)   err.remove();
}

// ── Name validation ────────────────────────────────────────
function validateName(input) {
  const v = input.value.trim();
  if (!v) { showInlineErr(input, 'Full Name is required.'); }
  else if (v.length < 2) { showInlineErr(input, 'Full Name must be at least 2 characters.'); }
  else if (!/^[a-zA-Z\s\-'\.]+$/.test(v)) { showInlineErr(input, 'Full Name must contain letters only.'); }
  else { clearErr('name'); showInlineSuccess(input); }
}

// ── Email validation ───────────────────────────────────────
function validateEmail(input) {
  const v = input.value.trim();
  if (!v) { showInlineErr(input, 'Email Address is required.'); }
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) { showInlineErr(input, 'Please enter a valid email address.'); }
  else { clearErr('email'); showInlineSuccess(input); }
}

// ── Password strength ──────────────────────────────────────
function updateStrength(pw) {
  const rules = {
    'rule-len':     pw.length >= 8,
    'rule-upper':   /[A-Z]/.test(pw),
    'rule-lower':   /[a-z]/.test(pw),
    'rule-num':     /[0-9]/.test(pw),
    'rule-special': /[^A-Za-z0-9]/.test(pw),
  };
  let score = Object.values(rules).filter(Boolean).length;
  Object.entries(rules).forEach(([id, met]) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('met', met);
  });
  const colors = ['','#ef4444','#f59e0b','#a3e635','#22c55e','#22c55e'];
  const labels = ['','Weak','Fair','Good','Strong','Very Strong'];
  for (let i = 1; i <= 4; i++) {
    const bar = document.getElementById('bar'+i);
    bar.className = 'pw-bar' + (i <= score ? ` active-${Math.min(score,4)}` : '');
    if (i <= score) bar.style.background = colors[Math.min(score,4)];
    else bar.style.background = '';
  }
  const lbl = document.getElementById('pwLabel');
  lbl.textContent = pw.length ? labels[Math.min(score,4)] : '';
  lbl.style.color = colors[Math.min(score,4)];
}

// ── Confirm match ──────────────────────────────────────────
function checkMatch() {
  const pw  = document.getElementById('password').value;
  const cpw = document.getElementById('confirm_password');
  const ok  = document.getElementById('matchOk');
  if (!cpw.value) return;
  if (pw !== cpw.value) {
    showInlineErr(cpw, 'Confirm Password does not match.');
    ok.style.display = 'none';
  } else {
    clearErr('confirm_password');
    cpw.classList.add('is-success');
    ok.style.display = 'flex';
  }
}

// ── Show inline error/success ──────────────────────────────
function showInlineErr(input, msg) {
  input.classList.add('is-error');
  input.classList.remove('is-success');
  let err = input.closest('.form-group').querySelector('.field-error');
  if (!err) {
    err = document.createElement('div');
    err.className = 'field-error';
    input.closest('.input-wrap').after(err);
  }
  err.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${msg}`;
}
function showInlineSuccess(input) {
  input.classList.add('is-success');
  input.classList.remove('is-error');
}

// ── Register form submit validation ───────────────────────
document.getElementById('registerForm')?.addEventListener('submit', function(e) {
  let ok = true;
  const name  = document.getElementById('name');
  const email = document.getElementById('email');
  const pw    = document.getElementById('password');
  const cpw   = document.getElementById('confirm_password');
  const terms = document.getElementById('terms');

  if (!name.value.trim()) { showInlineErr(name, 'Full Name is required.'); ok = false; }
  else if (name.value.trim().length < 2) { showInlineErr(name, 'Full Name must be at least 2 characters.'); ok = false; }

  if (!email.value.trim()) { showInlineErr(email, 'Email Address is required.'); ok = false; }
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) { showInlineErr(email, 'Please enter a valid email address.'); ok = false; }

  if (!pw.value) { showInlineErr(pw, 'Password is required.'); ok = false; }
  else if (pw.value.length < 8) { showInlineErr(pw, 'Password must be at least 8 characters.'); ok = false; }

  if (!cpw.value) { showInlineErr(cpw, 'Please confirm your password.'); ok = false; }
  else if (pw.value !== cpw.value) { showInlineErr(cpw, 'Confirm Password does not match.'); ok = false; }

  if (!terms.checked) {
    let err = terms.closest('.form-group').querySelector('.field-error');
    if (!err) {
      err = document.createElement('div'); err.className = 'field-error';
      terms.closest('.check-wrap').after(err);
    }
    err.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>You must agree to the Terms & Conditions.`;
    ok = false;
  }

  if (!ok) { e.preventDefault(); return; }
  document.getElementById('registerBtn').classList.add('loading');
});

// ── OTP inputs auto-advance ────────────────────────────────
function otpInput(el, pos) {
  el.value = el.value.replace(/\D/g, '').slice(-1);
  el.classList.toggle('filled', el.value !== '');
  el.classList.remove('is-error');
  if (el.value && pos < 6) document.getElementById('otp'+(pos+1)).focus();
  if (pos === 6 && el.value) {
    // Auto-submit when all filled
    const all = [...Array(6)].every((_,i) => document.getElementById('otp'+(i+1)).value);
    if (all) setTimeout(() => document.getElementById('otpForm').submit(), 200);
  }
}
function otpKeydown(e, pos) {
  if (e.key === 'Backspace' && !e.target.value && pos > 1) {
    document.getElementById('otp'+(pos-1)).focus();
  }
  if (e.key === 'ArrowLeft' && pos > 1) document.getElementById('otp'+(pos-1)).focus();
  if (e.key === 'ArrowRight' && pos < 6) document.getElementById('otp'+(pos+1)).focus();
}
function otpPaste(e) {
  e.preventDefault();
  const text = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g,'').slice(0,6);
  [...text].forEach((ch, i) => {
    const inp = document.getElementById('otp'+(i+1));
    if (inp) { inp.value = ch; inp.classList.add('filled'); }
  });
  const next = Math.min(text.length + 1, 6);
  document.getElementById('otp'+next)?.focus();
}

// ── OTP Countdown timer ────────────────────────────────────
let seconds = <?= OTP_EXPIRY_MINUTES * 60 ?>;
const countdown = document.getElementById('countdown');
const timerWrap = document.getElementById('timerWrap');
const expiredMsg= document.getElementById('expiredMsg');

if (countdown) {
  const t = setInterval(() => {
    seconds--;
    if (seconds <= 0) {
      clearInterval(t);
      timerWrap.style.display = 'none';
      expiredMsg.style.display = 'block';
      document.getElementById('verifyBtn').disabled = true;
      return;
    }
    const m = Math.floor(seconds/60), s = seconds%60;
    countdown.textContent = m+':'+(s<10?'0':'')+s;
    if (seconds <= 60) countdown.style.color = 'var(--danger)';
  }, 1000);
}

// OTP submit loading
document.getElementById('otpForm')?.addEventListener('submit', function() {
  document.getElementById('verifyBtn')?.classList.add('loading');
});
</script>
</body>
</html>