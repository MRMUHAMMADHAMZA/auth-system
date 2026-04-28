<?php
require_once __DIR__.'/config/config.php';
require_once __DIR__.'/includes/auth.php';
startSecureSession();
requireLogin();

$pdo  = getDB();
$user = $pdo->prepare("SELECT * FROM users WHERE id=?");
$user->execute([(int)$_SESSION['user_id']]);
$user = $user->fetch();
$init = getAvatarInitials($user['name']);
$flash= getFlash();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Home — <?= APP_NAME ?></title>
  <link rel="stylesheet" href="<?= APP_URL ?>/assets/css/style.css">
</head>
<body>
<div class="bg-blobs">
  <div class="blob blob-1"></div><div class="blob blob-2"></div><div class="blob blob-3"></div>
</div>
<div class="auth-page">
  <div class="home-card">

    <?php if ($flash): ?>
      <div class="alert alert--<?= h($flash['type']) ?>">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <?= h($flash['msg']) ?>
      </div>
    <?php endif; ?>

    <div class="home-header">
      <div class="home-user">
        <div class="avatar" style="background:<?= h($user['avatar_color']) ?>"><?= h($init) ?></div>
        <div>
          <div style="font-size:1.1rem;font-weight:600;color:var(--text)"><?= h($user['name']) ?></div>
          <div style="font-size:.8rem;color:var(--text3)"><?= h($user['email']) ?></div>
        </div>
      </div>
      <a href="<?= APP_URL ?>/logout.php" class="btn btn--outline" style="width:auto;padding:9px 18px;font-size:.82rem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="14" height="14"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Sign Out
      </a>
    </div>

    <!-- Verified badge -->
    <?php if (!$user['is_verified']): ?>
    <div class="alert alert--warning">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      Your email is not verified yet.
    </div>
    <?php else: ?>
    <div class="alert alert--success">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="16" height="16"><polyline points="20 6 9 17 4 12"/></svg>
      Email verified · Account is active ✓
    </div>
    <?php endif; ?>

    <div style="font-size:.78rem;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px">Account Details</div>
    <div class="info-grid">
      <div class="info-item">
        <div class="info-label">Full Name</div>
        <div class="info-value"><?= h($user['name']) ?></div>
      </div>
      <div class="info-item">
        <div class="info-label">Email</div>
        <div class="info-value" style="word-break:break-all"><?= h($user['email']) ?></div>
      </div>
      <div class="info-item">
        <div class="info-label">Account Status</div>
        <div class="info-value" style="color:<?= $user['is_active']?'var(--success)':'var(--danger)' ?>"><?= $user['is_active']?'Active':'Inactive' ?></div>
      </div>
      <div class="info-item">
        <div class="info-label">Email Verified</div>
        <div class="info-value" style="color:<?= $user['is_verified']?'var(--success)':'var(--warning)' ?>"><?= $user['is_verified']?'Verified ✓':'Not Verified' ?></div>
      </div>
      <div class="info-item">
        <div class="info-label">Last Login</div>
        <div class="info-value"><?= $user['last_login']?date('M d, Y g:i A',strtotime($user['last_login'])):'First login' ?></div>
      </div>
      <div class="info-item">
        <div class="info-label">Member Since</div>
        <div class="info-value"><?= date('M d, Y', strtotime($user['created_at'])) ?></div>
      </div>
    </div>

    <div style="margin-top:20px;display:flex;gap:10px;flex-wrap:wrap">
      <a href="<?= APP_URL ?>/change_password.php" class="btn btn--outline" style="width:auto;flex:1">Change Password</a>
    </div>

  </div>
</div>
</body>
</html>
