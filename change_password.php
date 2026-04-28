<?php
require_once __DIR__.'/config/config.php';
require_once __DIR__.'/includes/auth.php';
startSecureSession();
requireLogin();

$errors = []; $success = false;
$uid    = (int)$_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors['global'] = 'Invalid request.';
    } else {
        $v = validate($_POST)
            ->required('current_password', 'Current Password')
            ->required('new_password',     'New Password')
            ->password('new_password',     'New Password')
            ->required('confirm_password', 'Confirm Password')
            ->matches('confirm_password',  'new_password', 'Confirm Password');

        if ($v->fails()) {
            $errors = $v->errors();
        } else {
            $pdo  = getDB();
            $u    = $pdo->prepare("SELECT password FROM users WHERE id=?"); $u->execute([$uid]); $u=$u->fetch();
            if (!password_verify($_POST['current_password'], $u['password'])) {
                $errors['current_password'] = 'Current password is incorrect.';
            } else {
                $hash = password_hash($_POST['new_password'], PASSWORD_BCRYPT, ['cost' => 12]);
                $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([$hash, $uid]);
                setFlash('success', '✓ Password changed successfully!');
                header('Location: '.APP_URL.'/home.php'); exit;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Change Password — <?= APP_NAME ?></title>
  <link rel="stylesheet" href="<?= APP_URL ?>/assets/css/style.css">
</head>
<body>
<div class="bg-blobs"><div class="blob blob-1"></div><div class="blob blob-2"></div></div>
<div class="auth-page">
  <div class="auth-card">
    <div class="auth-logo"><div class="logo-icon">🔐</div><div class="logo-text"><?= APP_NAME ?></div></div>
    <div class="auth-header"><h1>Change Password</h1><p>Update your account password</p></div>

    <?php if (!empty($errors['global'])): ?>
      <div class="alert alert--error"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg><?= h($errors['global']) ?></div>
    <?php endif; ?>

    <form method="POST" novalidate>
      <?= csrfField() ?>

      <div class="form-group">
        <label>Current Password <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" name="current_password" placeholder="Your current password"
            class="<?= !empty($errors['current_password'])?'is-error':'' ?>" required>
          <svg class="icon-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" onclick="tp(this)"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <?php if (!empty($errors['current_password'])): ?>
          <div class="field-error"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="12" height="12"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><?= h($errors['current_password']) ?></div>
        <?php endif; ?>
      </div>

      <div class="form-group">
        <label>New Password <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" id="npw" name="new_password" placeholder="New password"
            class="<?= !empty($errors['new_password'])?'is-error':'' ?>"
            oninput="updateStrength(this.value)" required>
          <svg class="icon-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" onclick="tp(this)"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <?php if (!empty($errors['new_password'])): ?>
          <div class="field-error"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="12" height="12"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><?= h($errors['new_password']) ?></div>
        <?php endif; ?>
        <div class="pw-strength"><div class="pw-bars"><div class="pw-bar" id="bar1"></div><div class="pw-bar" id="bar2"></div><div class="pw-bar" id="bar3"></div><div class="pw-bar" id="bar4"></div></div><div class="pw-label" id="pwLabel"></div></div>
        <div class="pw-rules">
          <div class="pw-rule" id="rule-len"><div class="dot"></div>At least 8 characters</div>
          <div class="pw-rule" id="rule-upper"><div class="dot"></div>One uppercase letter</div>
          <div class="pw-rule" id="rule-num"><div class="dot"></div>One number</div>
          <div class="pw-rule" id="rule-special"><div class="dot"></div>One special character</div>
        </div>
      </div>

      <div class="form-group">
        <label>Confirm New Password <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="icon-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" id="cpw" name="confirm_password" placeholder="Repeat new password"
            class="<?= !empty($errors['confirm_password'])?'is-error':'' ?>"
            oninput="checkMatch()" required>
          <svg class="icon-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" onclick="tp(this)"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <?php if (!empty($errors['confirm_password'])): ?>
          <div class="field-error"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="12" height="12"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><?= h($errors['confirm_password']) ?></div>
        <?php endif; ?>
        <div class="field-success" id="matchOk" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="12" height="12"><polyline points="20 6 9 17 4 12"/></svg>Passwords match</div>
      </div>

      <button type="submit" class="btn btn--primary">Update Password</button>
    </form>
    <div class="auth-footer"><a href="<?= APP_URL ?>/home.php">← Back to Home</a></div>
  </div>
</div>
<script>
function tp(icon){const input=icon.closest('.input-wrap').querySelector('input');input.type=input.type==='password'?'text':'password';}
function updateStrength(pw){
  const r={'rule-len':pw.length>=8,'rule-upper':/[A-Z]/.test(pw),'rule-num':/[0-9]/.test(pw),'rule-special':/[^A-Za-z0-9]/.test(pw)};
  let s=Object.values(r).filter(Boolean).length;
  Object.entries(r).forEach(([id,m])=>{const el=document.getElementById(id);if(el)el.classList.toggle('met',m);});
  const c=['','#ef4444','#f59e0b','#a3e635','#22c55e'],l=['','Weak','Fair','Good','Strong'];
  for(let i=1;i<=4;i++){const b=document.getElementById('bar'+i);if(b){b.className='pw-bar'+(i<=s?` active-${Math.min(s,4)}`:'');b.style.background=i<=s?c[Math.min(s,4)]:''}}
  const lbl=document.getElementById('pwLabel');if(lbl){lbl.textContent=pw.length?(l[Math.min(s,4)]||''):'';lbl.style.color=c[Math.min(s,4)];}
}
function checkMatch(){
  const pw=document.getElementById('npw')?.value,cpw=document.getElementById('cpw'),ok=document.getElementById('matchOk');
  if(!cpw.value)return;
  if(pw!==cpw.value){cpw.classList.add('is-error');if(ok)ok.style.display='none';}
  else{cpw.classList.remove('is-error');cpw.classList.add('is-success');if(ok)ok.style.display='flex';}
}
</script>
</body>
</html>
