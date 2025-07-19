# 🔐 Cybersecurity Project – OWASP-Compliant 2FA OTP Verification System

This is a **Cybersecurity-focused project** implementing a secure, production-ready **Two-Factor Authentication (2FA)** system using **TOTP (Time-based One-Time Password)** and **SMS OTP** delivery via Twilio. The system strictly follows the **OWASP 2025–26** and **ASVS Level 2+ guidelines**, incorporating strong security mechanisms like replay protection, adaptive authentication, recovery flows etc.

---

## 🛡️ Project Objective

**To design and implement a secure multi-factor authentication (MFA) system that mitigates common OTP-based attacks** such as OTP replay, brute-force guessing, SIM-swapping, session hijacking, and device impersonation.

This project demonstrates deep practical application of **Cybersecurity principles** in web authentication by integrating cryptography, secure session management, risk-based access, and OWASP best practices.

---

## 🚀 Features

✅ TOTP-based OTP generation (RFC 6238)  
✅ Secure OTP delivery via Twilio SMS  
✅ Rate-limiting (Flask-Limiter) to prevent brute-force attacks  
✅ Secure session and replay protection  
✅ Device fingerprinting using IP + User-Agent hash  
✅ OTP expiration + reuse detection  
✅ Backup recovery code mechanism  
✅ MFA revocation flow  
✅ Step-up authentication for sensitive operations  
✅ Detailed logging and audit trail  
✅ Hardened using OWASP ASVS 2025-26 security controls

---

## 🧱 Tech Stack

- **Backend**: Flask, PyOTP, Twilio SDK, Flask-Limiter
- **Security**: pyotp, secrets, hashlib, HSTS, session hardening
- **Logging**: Python `logging`, IP and User-Agent capture
- **Rate Limiting**: Flask-Limiter (e.g., `5 per minute`)

---

## 📂 Directory Structure

```
project/
│
├── app.py                   # Main Flask app
├── static/
│   └── details.json         # Twilio credentials
├── templates/
│   ├── index.html           # Phone number input
│   ├── verify.html          # OTP input
│   └── show_qr.html         # QR provisioning
├── logs/
│   └── otp_activity.log     # Audit trail log
└── README.md                # This file
```

---

## 🔒 Security Highlights (OWASP 2025)

| Security Control | Implementation |
|------------------|----------------|
| **ASVS V2.1** | OTPs are TOTP-based with 30s expiry and single-use only |
| **ASVS V2.2** | Rate limiting prevents brute-force OTP attacks |
| **ASVS V2.5** | Reuse of last OTP is blocked with a warning |
| **ASVS V2.8** | One-time backup recovery codes provided |
| **ASVS V2.10** | Device fingerprinting via hashed IP + User-Agent |
| **ASVS V2.11** | Step-up MFA required before changing sensitive data |
| **ASVS V2.12** | All communication over HTTPS with HSTS headers |
| **ASVS V2.14** | MFA tokens can be revoked by user |
| **ASVS V2.15** | All authentication events are logged with metadata |

---

## 🛠️ Setup Instructions

### 1. Clone the repo
```bash
git clone https://github.com/Ankush703-web/Cybersecurity-OWASP-2025-Compliant-2FA-OTP-Verification.git
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Add your Twilio credentials

Edit `static/details.json`:
```json
{
  "twilio_account_sid": "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "twilio_auth_token": "your_twilio_auth_token",
  "twilio_phone_number": "+1234567890"
}
```

### 4. Run the app
```bash
python app.py
```

Visit: [http://localhost:5000](http://localhost:5000)

---

## 🧪 Test Scenarios

| Test Case                             | Expected Behavior |
|--------------------------------------|-------------------|
| OTP entered within time              | ✅ Verified |
| OTP expired                          | ❌ Rejected |
| OTP reused                           | ❌ Rejected |
| 5 incorrect attempts                 | 🔒 Temporary lockout |
| Valid recovery code used             | ⚠️ Warning + Success |
| Step-up required (e.g., new device)  | 🔁 TOTP re-verification |
| MFA credentials revoked              | 🔐 OTPs become invalid |

---

## 📋 Cybersecurity Concepts Demonstrated

- Multi-Factor Authentication (MFA)
- Rate Limiting and Throttling
- OTP Expiration and Replay Protection
- Session Hardening and Secure Storage
- Adaptive Authentication (IP + Device-Aware)
- Secure Delivery Channels (SMS over HTTPS)
- Recovery Flow for MFA Failures
- Revocation of Auth Credentials
- Secure OTP Lifecycle Management
- OWASP Top 10 and ASVS Compliance

---

## 📜 License

This project is licensed under the MIT License.

---

## 🙌 Acknowledgments

- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [OWASP ASVS 4.0](https://owasp.org/www-project-application-security-verification-standard/)
- [Twilio API for Programmable SMS](https://www.twilio.com/docs/sms)

---

## 📣 About the Author

This cybersecurity project was developed by **Ankush** as part of advancement in **Web Security** and **Secure Authentication Systems**.  
