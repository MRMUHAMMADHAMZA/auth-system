# 🔐 AuthPro — PHP Authentication System

A complete, secure, and fully responsive authentication system built with **PHP 8** and **MySQL**. Includes Sign In, Sign Up, Forgot Password, and Reset Password with **OTP email verification**.

---

## 🚀 Live Demo

> Deploy to a PHP host and update `APP_URL` in `config/config.php`

**Test Credentials:**
| Email | Password |
|-------|----------|
| admin@test.com | Test@1234 |

---

## ✨ Features

### 🔑 Authentication Pages
- **Sign In** — Email + password login with remember me
- **Sign Up** — Full registration with email OTP verification
- **Forgot Password** — Request OTP via email
- **Reset Password** — 3-step flow: Email → OTP → New Password
- **Change Password** — Update password when logged in
- **Dashboard** — User profile with account info

### ✅ Validation (Client + Server)
Every field is validated on **both sides**:

| Field | Rules |
|-------|-------|
| Full Name | Required · Letters only · Min 2 · Max 100 chars |
| Email | Required · Valid format · Unique in database |
| Password | Required · 8+ chars · Uppercase · Lowercase · Number · Special char |
| Confirm Password | Required · Must match password |
| Terms | Must be accepted |
| OTP | Required · Exactly 6 digits · Expiry check · Attempt limit |

### 🔒 Security Features
| Feature | Implementation |
|---------|---------------|
| Password Hashing | `bcrypt` cost-12 |
| SQL Injection | PDO prepared statements throughout |
| CSRF Protection | Token on every form |
| Brute Force | 5 attempts → 15 min IP lockout |
| Session Security | HttpOnly + SameSite=Strict cookies |
| Session Fixation | `session_regenerate_id()` on login |
| XSS Prevention | `htmlspecialchars()` on all output |
| OTP Security | 10 min expiry · Max 3 wrong attempts · 60s resend cooldown |
| Rate Limiting | Per IP + per email |

### 📧 OTP System
- 6-digit random OTP sent to email
- 10-minute expiry with live countdown timer
- Auto-submits when all 6 digits entered
- Max 3 wrong attempts before invalidation
- 60-second resend cooldown
- DEV MODE shows OTP on screen for local testing

---

## 📁 Project Structure

```
auth-system/
├── index.php               ← Sign In
├── register.php            ← Sign Up + Email OTP Verify
├── forgot_password.php     ← Request Password Reset OTP
├── reset_password.php      ← OTP Verify + New Password
├── change_password.php     ← Change Password (logged in)
├── home.php                ← Dashboard after login
├── logout.php              ← Secure logout
│
├── config/
│   ├── config.php          ← App settings & constants
│   ├── db.php              ← PDO database connection (gitignored)
│   └── db.example.php      ← DB config template
│
├── includes/
│   ├── auth.php            ← Login, register, OTP, session logic
│   └── validator.php       ← All field validation rules
│
├── assets/
│   └── css/
│       └── style.css       ← Full responsive dark UI
│
└── sql/
    └── schema.sql          ← Database schema + seed data
```

---

## ⚡ Quick Setup (XAMPP)

### 1. Clone the repo
```bash
git clone https://github.com/MRMUHAMMADHAMZA/auth-system.git
```

### 2. Copy to XAMPP
```
C:\xampp\htdocs\auth-system\
```

### 3. Import database
- Open `http://localhost/phpmyadmin`
- Create database: `auth_db`
- Click **Import** → select `sql/schema.sql` → **Go**

### 4. Configure database
Copy `config/db.example.php` → rename to `config/db.php`:
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'auth_db');
define('DB_USER', 'root');
define('DB_PASS', '');
```

### 5. Set app URL
Edit `config/config.php`:
```php
define('APP_URL', 'http://localhost/auth-system');
define('DEBUG_MODE', true); // Shows OTP on screen for local testing
```

### 6. Open in browser
```
http://localhost/auth-system/
```

---

## 📧 Email / OTP Setup

### Local Testing (No email needed)
Set `DEBUG_MODE = true` in `config/config.php`.
The OTP will appear in a **yellow box on screen** — no SMTP required.

### Using Mailtrap (Recommended for dev)
1. Sign up free at [mailtrap.io](https://mailtrap.io)
2. Go to **Email Testing → Inboxes → SMTP Settings → PHP**
3. Update `config/config.php`:
```php
define('USE_SMTP',   true);
define('SMTP_HOST',  'sandbox.smtp.mailtrap.io');
define('SMTP_PORT',  2525);
define('SMTP_USER',  'your_mailtrap_username');
define('SMTP_PASS',  'your_mailtrap_password');
```

### Gmail (Live Server)
1. Enable 2FA on your Google account
2. Generate an **App Password** (Google Account → Security → App Passwords)
3. Update config:
```php
define('USE_SMTP',   true);
define('SMTP_HOST',  'smtp.gmail.com');
define('SMTP_PORT',  587);
define('SMTP_USER',  'your@gmail.com');
define('SMTP_PASS',  'your_16_char_app_password');
```

---

## 🖥️ Screenshots

### Sign In
> Clean dark UI with animated background blobs, real-time field validation

### Sign Up
> Password strength meter, rules checklist, confirm match feedback

### OTP Verification
> 6-box OTP input with auto-advance, countdown timer, resend cooldown

### Reset Password
> 3-step flow with progress indicator: Email → OTP → New Password

---

## 🛠️ Tech Stack

| Technology | Usage |
|-----------|-------|
| PHP 8.0+ | Backend logic |
| MySQL 5.7+ | Database |
| PDO | Secure database queries |
| HTML5 / CSS3 | Frontend |
| Vanilla JavaScript | Client-side validation + OTP UX |
| Google Fonts | Plus Jakarta Sans + JetBrains Mono |

---

## 🔧 Configuration Options

| Constant | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | AuthPro | Application name |
| `APP_URL` | localhost/auth-system | Base URL |
| `SESSION_LIFETIME` | 7200 | Session timeout in seconds |
| `MAX_LOGIN_ATTEMPTS` | 5 | Failed logins before lockout |
| `LOCKOUT_MINUTES` | 15 | IP lockout duration |
| `OTP_EXPIRY_MINUTES` | 10 | OTP validity window |
| `OTP_MAX_ATTEMPTS` | 3 | Wrong OTP tries allowed |
| `OTP_RESEND_COOLDOWN` | 60 | Seconds before resend allowed |
| `DEBUG_MODE` | true | Show OTP on screen (dev only) |

---

## 🚀 Production Checklist

- [ ] Set `DEBUG_MODE = false`
- [ ] Configure real SMTP (Mailtrap or Gmail)
- [ ] Enable HTTPS and set `secure => true` in session cookie
- [ ] Change default test user password
- [ ] Move `config/` outside webroot or protect with `.htaccess`
- [ ] Set up error logging to file

---

## 📄 License

MIT License — free to use, modify and distribute.

---

Built with ❤️ by [Muhammad Hamza](https://github.com/MRMUHAMMADHAMZA) · [workbyhamza.com](https://workbyhamza.com)