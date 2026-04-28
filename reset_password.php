<?php
require_once __DIR__.'/config/config.php';
require_once __DIR__.'/includes/auth.php';
startSecureSession();
redirectIfLoggedIn();

$errors = [];
$step   = isset($_SESSION['reset_verified']) ? 'new_password' : 'verify_otp';
$email  = $_SESSION['reset_email'] ?? '';

if (!$email) { header('Location: '.APP_URL.'/forgot_password.php'); exit; }

// ── Resend OTP ─────────────────────────────────────────────
if (isset($_POST['resend_otp'])) {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) { $errors['global'] = 'Invalid request.'; }
    elseif (!canResendOtp($email, 'reset_password')) {
        $wait = getResendCooldown($email, 'reset_password');
        $errors['otp'] = "Please wait $wait second(s) before resending.";
    } else {
        $pdo = getDB();
        $u   = $pdo->prepare("SELECT name FROM users WHERE email=?"); $u->execute([$email]); $u=$u->fetch();
        $otp = generateOtp($email, 'reset_password');
        sendOtpEmail($email, $otp, 'reset_password', $u['name'] ?? '');
        setFlash('success', 'New OTP sent to your email.');
        header('Location: '.APP_URL.'/reset_password.php'); exit;
    }
}

// ── Verify OTP step ────────────────────────────────────────
if ($step === 'verify_otp' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['otp_1'])) {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) { $errors['global'] = 'Invalid request.'; }
    else {
        $code   = implode('', array_map(fn($i) => preg_replace('/\D/', '', $_POST["otp_$i"] ?? ''), range(1, 6)));
        $result = verifyOtp($email, $code, 'reset_password');
        if ($result['success']) {
            $_SESSION['reset_verified'] = true;
            $step = 'new_password';
        } else {
            $errors = $result['errors'];
        }
    }
}

// ── New password step ──────────────────────────────────────
if ($step === 'new_password' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) { $errors['global'] = 'Invalid request.'; }
    else {
        $result = resetPassword($email, $_POST['password'] ?? '', $_POST['confirm_password'] ?? '');
        if ($result['success']) {
            unset($_SESSION['reset_email'], $_SESSION['reset_verified'], $_SESSION['debug_otp']);
            setFlash('success', '✓ Password reset successfully! Please sign in with your new password.');
            header('Location: '.APP_URL.'/index.php'); exit;
        }
        $errors = $result['errors'];
    }
}

$flash = getFlash();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password — <?= APP_NAME ?></title>
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

    <!-- Steps -->
    <div class="steps">
      <div class="step-item done">
        <div class="step-dot">✓</div>
        <div class="step-label">Email</div>
      </div>
      <div class="step-item <?= $step==='verify_otp'?'active':'done' ?>">
        <div class="step-dot"><?= $step==='new_password'?'✓':'2' ?></div>
        <div class="step-label">Verify OTP</div>
      </div>
      <div class="step-item <?= $step==='new_password'?'active':'' ?>">
        <div class="step-dot">3</div>
        <div class="step-label">New Password</div>
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

    <?php if ($step === 'verify_otp'): ?>
    <!-- ── OTP Step ── -->
    <div class="auth-header">
      <h1>Enter OTP</h1>
      <p>We sent a 6-digit code to your email</p>
    </div>

    <?php if (DEBUG_MODE && isset($_SESSION['debug_otp'])): ?>
    <div class="debug-box">
      <strong>🛠 DEV MODE — OTP Code:</strong>
      <div class="debug-otp"><?= h($_SESSION['debug_otp']) ?></div>
    </div>
    <?php endif; ?>

    <div class="otp-info">
      <div class="otp-email">Code sent to <strong><?= h($email) ?></strong></div>
    </div>

    <?php if (!empty($errors['otp'])): ?>
      <div class="alert alert--error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <?= h($errors['otp']) ?>
      </div>
    <?php endif; ?>

    <form method="POST" id="otpForm">
      <?= csrfField() ?>
      <div class="otp-inputs">
        <?php for($i=1;$i<=6;$i++): ?>
          <input type="text" name="otp_<?= $i ?>" id="otp<?= $i ?>"
            maxlength="1" pattern="\d" inputmode="numeric"
            class="<?= !empty($errors['otp'])?'is-error':'' ?>"
            oninput="otpInput(this,<?= $i ?>)"
            onkeydown="otpKeydown(event,<?= $i ?>)"
            onpaste="otpPaste(event)">
        <?php endfor; ?>
      </div>
      <div class="otp-info mt-8">
        <div class="otp-timer" id="timerWrap">Expires in <span id="countdown"><?= OTP_EXPIRY_MINUTES ?>:00</span></div>
        <div id="expiredMsg" style="display:none;font-size:.8rem;color:var(--danger)">Code expired. Please resend.</div>
      </div>
      <button type="submit" class="btn btn--primary mt-16" id="verifyBtn">
        <span class="btn-text">Verify OTP →</span>
        <div class="spinner"></div>
      </button>
    </form>

    <div class="text-center mt-16">
      <form method="POST" style="display:inline">
        <?= csrfField() ?>
        <input type="hidden" name="resend_otp" value="1">
        <button type="submit" class="resend-btn">Resend OTP</button>
      </form>
    </div>

    <?php else: ?>
    <!-- ── New Password Step ── -->
    <div class="auth-header">
      <h1>New password</h1>
      <p>Create a strong password for your account</p>
    </div>

    <form method="POST" id="pwForm" novalidate>
      <?= csrfField() ?>

      <!-- New Password -->
      <div class="form-group">
        <label for="password">New Password <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" id="password" name="password" placeholder="Min 8 chars"
            class="<?= !empty($errors['password']) ? 'is-error' : '' ?>"
            autocomplete="new-password"
            oninput="clearFieldErr('password'); updateStrength(this.value); checkMatch()">
          <svg class="icon-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" onclick="togglePw('password',this)"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <?php if (!empty($errors['password'])): ?>
          <div class="field-error">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['password']) ?>
          </div>
        <?php endif; ?>
        <div class="pw-strength">
          <div class="pw-bars">
            <div class="pw-bar" id="bar1"></div><div class="pw-bar" id="bar2"></div>
            <div class="pw-bar" id="bar3"></div><div class="pw-bar" id="bar4"></div>
          </div>
          <div class="pw-label" id="pwLabel"></div>
        </div>
        <div class="pw-rules">
          <div class="pw-rule" id="rule-len"><div class="dot"></div>At least 8 characters</div>
          <div class="pw-rule" id="rule-upper"><div class="dot"></div>One uppercase letter</div>
          <div class="pw-rule" id="rule-lower"><div class="dot"></div>One lowercase letter</div>
          <div class="pw-rule" id="rule-num"><div class="dot"></div>One number</div>
          <div class="pw-rule" id="rule-special"><div class="dot"></div>One special character</div>
        </div>
      </div>

      <!-- Confirm Password -->
      <div class="form-group">
        <label for="confirm_password">Confirm Password <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" id="confirm_password" name="confirm_password" placeholder="Repeat password"
            class="<?= !empty($errors['confirm_password']) ? 'is-error' : '' ?>"
            autocomplete="new-password"
            oninput="clearFieldErr('confirm_password'); checkMatch()">
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

      <button type="submit" class="btn btn--primary" id="resetBtn">
        <span class="btn-text">Reset Password ✓</span>
        <div class="spinner"></div>
      </button>
    </form>
    <?php endif; ?>

    <div class="auth-footer mt-16">
      <a href="<?= APP_URL ?>/index.php">← Back to Sign In</a>
    </div>

  </div>
</div>

<script>
// ── OTP auto-advance ────────────────────────────────────────
function otpInput(el, pos) {
  el.value = el.value.replace(/\D/g,'').slice(-1);
  el.classList.toggle('filled', el.value !== '');
  el.classList.remove('is-error');
  if (el.value && pos < 6) document.getElementById('otp'+(pos+1)).focus();
  if (pos === 6 && el.value) {
    const all = [...Array(6)].every((_,i) => document.getElementById('otp'+(i+1)).value);
    if (all) setTimeout(() => document.getElementById('otpForm').submit(), 200);
  }
}
function otpKeydown(e, pos) {
  if (e.key === 'Backspace' && !e.target.value && pos > 1) document.getElementById('otp'+(pos-1)).focus();
  if (e.key === 'ArrowLeft'  && pos > 1) document.getElementById('otp'+(pos-1)).focus();
  if (e.key === 'ArrowRight' && pos < 6) document.getElementById('otp'+(pos+1)).focus();
}
function otpPaste(e) {
  e.preventDefault();
  const text = (e.clipboardData||window.clipboardData).getData('text').replace(/\D/g,'').slice(0,6);
  [...text].forEach((ch,i) => { const inp=document.getElementById('otp'+(i+1)); if(inp){inp.value=ch;inp.classList.add('filled');} });
  document.getElementById('otp'+Math.min(text.length+1,6))?.focus();
}

// Countdown
let seconds = <?= OTP_EXPIRY_MINUTES * 60 ?>;
const cd = document.getElementById('countdown');
const tw = document.getElementById('timerWrap');
const ex = document.getElementById('expiredMsg');
if (cd) {
  const t = setInterval(() => {
    seconds--;
    if (seconds <= 0) { clearInterval(t); if(tw)tw.style.display='none'; if(ex)ex.style.display='block'; document.getElementById('verifyBtn').disabled=true; return; }
    cd.textContent = Math.floor(seconds/60)+':'+(seconds%60<10?'0':'')+seconds%60;
    if(seconds<=60) cd.style.color='var(--danger)';
  },1000);
}

document.getElementById('otpForm')?.addEventListener('submit',()=>document.getElementById('verifyBtn')?.classList.add('loading'));

// ── Password functions ──────────────────────────────────────
function togglePw(id) { const i=document.getElementById(id); i.type=i.type==='password'?'text':'password'; }
function clearFieldErr(field) {
  const input=document.querySelector(`[name="${field}"]`);
  const err=input?.closest('.form-group')?.querySelector('.field-error');
  if(input){input.classList.remove('is-error');}
  if(err) err.remove();
}
function updateStrength(pw) {
  const rules={'rule-len':pw.length>=8,'rule-upper':/[A-Z]/.test(pw),'rule-lower':/[a-z]/.test(pw),'rule-num':/[0-9]/.test(pw),'rule-special':/[^A-Za-z0-9]/.test(pw)};
  let score=Object.values(rules).filter(Boolean).length;
  Object.entries(rules).forEach(([id,met])=>{ const el=document.getElementById(id); if(el)el.classList.toggle('met',met); });
  const colors=['','#ef4444','#f59e0b','#a3e635','#22c55e','#22c55e'];
  const labels=['','Weak','Fair','Good','Strong','Very Strong'];
  for(let i=1;i<=4;i++){const b=document.getElementById('bar'+i);if(b){b.className='pw-bar'+(i<=score?` active-${Math.min(score,4)}`:'');b.style.background=i<=score?colors[Math.min(score,4)]:''}}
  const lbl=document.getElementById('pwLabel');if(lbl){lbl.textContent=pw.length?labels[Math.min(score,4)]:'';lbl.style.color=colors[Math.min(score,4)];}
}
function checkMatch() {
  const pw=document.getElementById('password')?.value;
  const cpw=document.getElementById('confirm_password');
  const ok=document.getElementById('matchOk');
  if(!cpw||!cpw.value)return;
  if(pw!==cpw.value){cpw.classList.add('is-error');if(ok)ok.style.display='none';}
  else{cpw.classList.remove('is-error');cpw.classList.add('is-success');if(ok)ok.style.display='flex';}
}

document.getElementById('pwForm')?.addEventListener('submit',function(e){
  let ok=true;
  const pw=document.getElementById('password');
  const cpw=document.getElementById('confirm_password');
  if(!pw.value){showErr(pw,'New Password is required.');ok=false;}
  else if(pw.value.length<8){showErr(pw,'Password must be at least 8 characters.');ok=false;}
  if(!cpw.value){showErr(cpw,'Please confirm your password.');ok=false;}
  else if(pw.value!==cpw.value){showErr(cpw,'Confirm Password does not match.');ok=false;}
  if(!ok){e.preventDefault();return;}
  document.getElementById('resetBtn').classList.add('loading');
});

function showErr(input,msg){
  input.classList.add('is-error');
  let err=input.closest('.form-group').querySelector('.field-error');
  if(!err){err=document.createElement('div');err.className='field-error';input.closest('.input-wrap').after(err);}
  err.innerHTML=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${msg}`;
}
</script>
</body>
</html>
