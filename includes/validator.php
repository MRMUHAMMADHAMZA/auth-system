<?php
// ============================================================
// VALIDATOR — All field-level validations
// ============================================================
class Validator {
    private array $errors = [];
    private array $data   = [];

    public function __construct(array $data) {
        $this->data = $data;
    }

    // ── Required ─────────────────────────────────────────────
    public function required(string $field, string $label): self {
        $val = trim($this->data[$field] ?? '');
        if ($val === '') {
            $this->errors[$field] = "$label is required.";
        }
        return $this;
    }

    // ── Min length ───────────────────────────────────────────
    public function minLength(string $field, string $label, int $min): self {
        if (isset($this->errors[$field])) return $this;
        $val = trim($this->data[$field] ?? '');
        if (strlen($val) < $min) {
            $this->errors[$field] = "$label must be at least $min characters.";
        }
        return $this;
    }

    // ── Max length ───────────────────────────────────────────
    public function maxLength(string $field, string $label, int $max): self {
        if (isset($this->errors[$field])) return $this;
        $val = trim($this->data[$field] ?? '');
        if (strlen($val) > $max) {
            $this->errors[$field] = "$label must not exceed $max characters.";
        }
        return $this;
    }

    // ── Valid email ──────────────────────────────────────────
    public function email(string $field, string $label = 'Email'): self {
        if (isset($this->errors[$field])) return $this;
        $val = trim($this->data[$field] ?? '');
        if (!filter_var($val, FILTER_VALIDATE_EMAIL)) {
            $this->errors[$field] = "Please enter a valid email address.";
        }
        return $this;
    }

    // ── Password strength ────────────────────────────────────
    public function password(string $field, string $label = 'Password'): self {
        if (isset($this->errors[$field])) return $this;
        $val = $this->data[$field] ?? '';
        if (strlen($val) < 8) {
            $this->errors[$field] = "$label must be at least 8 characters.";
        } elseif (!preg_match('/[A-Z]/', $val)) {
            $this->errors[$field] = "$label must contain at least one uppercase letter.";
        } elseif (!preg_match('/[a-z]/', $val)) {
            $this->errors[$field] = "$label must contain at least one lowercase letter.";
        } elseif (!preg_match('/[0-9]/', $val)) {
            $this->errors[$field] = "$label must contain at least one number.";
        } elseif (!preg_match('/[^A-Za-z0-9]/', $val)) {
            $this->errors[$field] = "$label must contain at least one special character (@, #, ! etc).";
        }
        return $this;
    }

    // ── Confirm match ────────────────────────────────────────
    public function matches(string $field, string $matchField, string $label): self {
        if (isset($this->errors[$field])) return $this;
        if (($this->data[$field] ?? '') !== ($this->data[$matchField] ?? '')) {
            $this->errors[$field] = "$label does not match.";
        }
        return $this;
    }

    // ── Only letters + spaces ─────────────────────────────────
    public function alpha(string $field, string $label): self {
        if (isset($this->errors[$field])) return $this;
        $val = trim($this->data[$field] ?? '');
        if (!preg_match('/^[a-zA-Z\s\-\'\.]+$/', $val)) {
            $this->errors[$field] = "$label must contain letters only.";
        }
        return $this;
    }

    // ── Numeric OTP ──────────────────────────────────────────
    public function otp(string $field): self {
        if (isset($this->errors[$field])) return $this;
        $val = trim($this->data[$field] ?? '');
        if ($val === '') {
            $this->errors[$field] = "OTP code is required.";
        } elseif (!preg_match('/^\d{6}$/', $val)) {
            $this->errors[$field] = "OTP must be exactly 6 digits.";
        }
        return $this;
    }

    // ── Checkbox must be checked ─────────────────────────────
    public function accepted(string $field, string $label): self {
        if (empty($this->data[$field])) {
            $this->errors[$field] = "You must agree to the $label.";
        }
        return $this;
    }

    // ── Unique email in DB ───────────────────────────────────
    public function uniqueEmail(string $field, int $excludeId = 0): self {
        if (isset($this->errors[$field])) return $this;
        $email = strtolower(trim($this->data[$field] ?? ''));
        $pdo   = getDB();
        $sql   = $excludeId
            ? "SELECT id FROM users WHERE email=? AND id!=? LIMIT 1"
            : "SELECT id FROM users WHERE email=? LIMIT 1";
        $s = $pdo->prepare($sql);
        $excludeId ? $s->execute([$email, $excludeId]) : $s->execute([$email]);
        if ($s->fetch()) {
            $this->errors[$field] = "This email address is already registered.";
        }
        return $this;
    }

    // ── Results ──────────────────────────────────────────────
    public function fails(): bool    { return !empty($this->errors); }
    public function passes(): bool   { return empty($this->errors); }
    public function errors(): array  { return $this->errors; }
    public function first(string $field): string { return $this->errors[$field] ?? ''; }
    public function get(string $field): string   { return trim($this->data[$field] ?? ''); }
}

// Helper to create validator
function validate(array $data): Validator {
    return new Validator($data);
}
