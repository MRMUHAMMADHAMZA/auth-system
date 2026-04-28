<?php
require_once __DIR__.'/config/config.php';
require_once __DIR__.'/includes/auth.php';
startSecureSession();
redirectIfLoggedIn();

$errors = []; $old = [];
$flash  = getFlash();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors['global'] = 'Invalid request. Please try again.';
    } else {
        $old    = $_POST;
        $result = loginUser($_POST['email'] ?? '', $_POST['password'] ?? '');
        if ($result['success']) {
            header('Location: '.APP_URL.'/home.php'); exit;
        }
        $errors = $result['errors'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — <?= APP_NAME ?></title>
  <link rel="stylesheet" href="<?= APP_URL ?>/assets/css/style.css">
</head>
<body>
<div class="bg-blobs">
  <div class="blob blob-1"></div>
  <div class="blob blob-2"></div>
  <div class="blob blob-3"></div>
</div>

<div class="auth-page">
  <div class="auth-card">

    <div class="auth-logo">
      <div class="logo-icon">🔐</div>
      <div class="logo-text"><?= APP_NAME ?></div>
    </div>

    <div class="auth-header">
      <h1>Welcome back</h1>
      <p>Sign in to your account to continue</p>
    </div>

    <!-- Flash message -->
    <?php if ($flash): ?>
      <div class="alert alert--<?= h($flash['type']) ?>">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <?= h($flash['msg']) ?>
      </div>
    <?php endif; ?>

    <!-- Global error -->
    <?php if (!empty($errors['global'])): ?>
      <div class="alert alert--error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <?= h($errors['global']) ?>
      </div>
    <?php endif; ?>

    <form method="POST" id="loginForm" novalidate>
      <?= csrfField() ?>

      <!-- Email -->
      <div class="form-group">
        <label for="email">Email Address <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
            <rect x="2" y="4" width="20" height="16" rx="3"/><path d="M2 8l10 7 10-7"/>
          </svg>
          <input
            type="email" id="email" name="email"
            placeholder="you@example.com"
            value="<?= old('email', $old) ?>"
            class="<?= !empty($errors['email']) ? 'is-error' : '' ?>"
            autocomplete="email"
            oninput="clearError('email')"
          >
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
        <div class="flex-between mb-4" style="margin-bottom:7px">
          <label for="password" style="margin:0">Password <span class="req">*</span></label>
          <a href="<?= APP_URL ?>/forgot_password.php" class="link">Forgot password?</a>
        </div>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
            <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <input
            type="password" id="password" name="password"
            placeholder="Your password"
            class="<?= !empty($errors['password']) ? 'is-error' : '' ?>"
            autocomplete="current-password"
            oninput="clearError('password')"
          >
          <svg class="icon-right" id="togglePw" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" onclick="togglePw('password','togglePw')">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
          </svg>
        </div>
        <?php if (!empty($errors['password'])): ?>
          <div class="field-error">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= h($errors['password']) ?>
          </div>
        <?php endif; ?>
      </div>

      <button type="submit" class="btn btn--primary mt-8" id="loginBtn">
        <span class="btn-text">Sign In →</span>
        <div class="spinner"></div>
      </button>
    </form>

    <div class="auth-footer">
      Don't have an account? <a href="<?= APP_URL ?>/register.php">Create one free</a>
    </div>

  </div>
</div>

<script>
function togglePw(inputId, iconId) {
  const input = document.getElementById(inputId);
  const icon  = document.getElementById(iconId);
  if (input.type === 'password') {
    input.type = 'text';
    icon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>';
  } else {
    input.type = 'password';
    icon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  }
}

function clearError(field) {
  const input = document.querySelector(`[name="${field}"]`);
  const err   = input?.closest('.form-group')?.querySelector('.field-error');
  if (input) input.classList.remove('is-error');
  if (err)   err.remove();
}

// Client-side validation before submit
document.getElementById('loginForm').addEventListener('submit', function(e) {
  let hasError = false;

  const email = document.getElementById('email');
  const pw    = document.getElementById('password');

  // Email required
  if (!email.value.trim()) {
    showError(email, 'Email Address is required.');
    hasError = true;
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) {
    showError(email, 'Please enter a valid email address.');
    hasError = true;
  }

  // Password required
  if (!pw.value) {
    showError(pw, 'Password is required.');
    hasError = true;
  }

  if (hasError) { e.preventDefault(); return; }

  // Show loading state
  document.getElementById('loginBtn').classList.add('loading');
});

function showError(input, msg) {
  input.classList.add('is-error');
  let err = input.closest('.form-group').querySelector('.field-error');
  if (!err) {
    err = document.createElement('div');
    err.className = 'field-error';
    err.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${msg}`;
    input.closest('.input-wrap').after(err);
  } else {
    err.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${msg}`;
  }
}
</script>
</body>
</html>
