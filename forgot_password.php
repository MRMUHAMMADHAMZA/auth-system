<?php
require_once __DIR__.'/config/config.php';
require_once __DIR__.'/includes/auth.php';
startSecureSession();
redirectIfLoggedIn();

$errors = []; $sent = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors['global'] = 'Invalid request. Please try again.';
    } else {
        $result = requestPasswordReset($_POST['email'] ?? '');
        if ($result['success']) {
            $_SESSION['reset_email'] = strtolower(trim($_POST['email'] ?? ''));
            $sent = true;
        } else {
            $errors = $result['errors'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forgot Password — <?= APP_NAME ?></title>
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

    <?php if ($sent): ?>
    <!-- ── Sent State ── -->
    <div class="success-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="2" y="4" width="20" height="16" rx="3"/><path d="M2 8l10 7 10-7"/></svg>
    </div>
    <div class="auth-header text-center">
      <h1>Check your inbox</h1>
      <p>If <strong style="color:var(--text)"><?= h($_POST['email'] ?? '') ?></strong> is registered, a 6-digit OTP has been sent.</p>
    </div>

    <?php if (DEBUG_MODE && isset($_SESSION['debug_otp'])): ?>
    <div class="debug-box">
      <strong>🛠 DEV MODE — OTP Code:</strong>
      <div class="debug-otp"><?= h($_SESSION['debug_otp']) ?></div>
    </div>
    <?php endif; ?>

    <a href="<?= APP_URL ?>/reset_password.php" class="btn btn--primary">
      <span class="btn-text">Enter OTP →</span>
    </a>
    <div class="auth-footer mt-16">
      <a href="<?= APP_URL ?>/index.php">← Back to Sign In</a>
    </div>

    <?php else: ?>
    <!-- ── Form State ── -->
    <div class="auth-header">
      <h1>Forgot password?</h1>
      <p>Enter your email and we'll send you a 6-digit OTP</p>
    </div>

    <?php if (!empty($errors['global'])): ?>
      <div class="alert alert--error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <?= h($errors['global']) ?>
      </div>
    <?php endif; ?>

    <form method="POST" id="forgotForm" novalidate>
      <?= csrfField() ?>

      <div class="form-group">
        <label for="email">Email Address <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="2" y="4" width="20" height="16" rx="3"/><path d="M2 8l10 7 10-7"/></svg>
          <input type="email" id="email" name="email" placeholder="your@email.com"
            value="<?= old('email', $_POST) ?>"
            class="<?= !empty($errors['email']) ? 'is-error' : '' ?>"
            autocomplete="email"
            oninput="validateEmail(this)">
        </div>
        <?php if (!empty($errors['email'])): ?>
          <div class="field-error">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['email']) ?>
          </div>
        <?php endif; ?>
        <div class="field-hint">We'll send a one-time code to this address</div>
      </div>

      <button type="submit" class="btn btn--primary" id="submitBtn">
        <span class="btn-text">Send OTP →</span>
        <div class="spinner"></div>
      </button>
    </form>

    <div class="auth-footer">
      Remembered it? <a href="<?= APP_URL ?>/index.php">Sign in</a>
    </div>
    <?php endif; ?>

  </div>
</div>

<script>
function validateEmail(input) {
  const v = input.value.trim();
  const err = input.closest('.form-group').querySelector('.field-error');
  if (!v) {
    input.classList.add('is-error');
    if (err) err.textContent = 'Email Address is required.';
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
    input.classList.add('is-error');
    if (err) err.textContent = 'Please enter a valid email address.';
  } else {
    input.classList.remove('is-error');
    input.classList.add('is-success');
    if (err) err.remove();
  }
}

document.getElementById('forgotForm')?.addEventListener('submit', function(e) {
  const email = document.getElementById('email');
  if (!email.value.trim()) {
    e.preventDefault();
    email.classList.add('is-error');
    let err = email.closest('.form-group').querySelector('.field-error');
    if (!err) {
      err = document.createElement('div'); err.className = 'field-error';
      err.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Email Address is required.`;
      email.closest('.input-wrap').after(err);
    }
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
    e.preventDefault();
    email.classList.add('is-error');
    return;
  }
  document.getElementById('submitBtn').classList.add('loading');
});
</script>
</body>
</html>
