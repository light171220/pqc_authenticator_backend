# How PQC Authenticator Works: A Complete Guide

## Table of Contents
1. [What is PQC Authenticator?](#what-is-pqc-authenticator)
2. [The Quantum Threat](#the-quantum-threat)
3. [How Traditional 2FA Works](#how-traditional-2fa-works)
4. [How Quantum-Safe 2FA Works](#how-quantum-safe-2fa-works)
5. [Core Technologies Explained](#core-technologies-explained)
6. [System Architecture](#system-architecture)
7. [Security Features](#security-features)
8. [Business Integration](#business-integration)
9. [Real-World Example](#real-world-example)
10. [Why This Matters](#why-this-matters)

---

## What is PQC Authenticator?

PQC Authenticator is a **quantum-safe two-factor authentication (2FA) system** that protects your digital accounts from both current cyber threats and future quantum computer attacks. Think of it as an ultra-secure version of Google Authenticator that will still work even when quantum computers become powerful enough to break today's encryption.

### What makes it special?
- **Future-proof**: Protected against quantum computers
- **Enterprise-ready**: Built for businesses with APIs and analytics
- **Cryptographically signed**: Each code is mathematically proven authentic
- **Self-rotating keys**: Automatically updates encryption keys for maximum security

---

## The Quantum Threat

### What are Quantum Computers?
Quantum computers are a completely different type of computer that use quantum physics to solve certain problems exponentially faster than regular computers. While they're amazing for scientific research, they pose a serious threat to current encryption methods.

### Why Should You Care?
Current 2FA systems (like Google Authenticator) use encryption methods that quantum computers could easily break. Here's the timeline:

- **Today**: Your 2FA codes are secure
- **2030-2035**: Quantum computers might break current encryption
- **Result**: All current 2FA systems could become useless overnight

### The Solution
PQC (Post-Quantum Cryptography) uses mathematical problems that even quantum computers can't solve efficiently. It's like building a lock that works against both regular lock picks AND futuristic quantum lock picks.

---

## How Traditional 2FA Works

### Step-by-Step Process:
1. **Setup**: You scan a QR code that contains a secret key
2. **Storage**: Your phone stores this secret key
3. **Code Generation**: Every 30 seconds, your phone combines:
   - The secret key
   - Current time
   - Uses HMAC-SHA1 algorithm
4. **Verification**: The server does the same calculation and compares

### The Problem:
- **HMAC-SHA1**: Vulnerable to quantum attacks
- **Static Keys**: Same secret key used forever
- **No Signatures**: Can't prove who generated the code

---

## How Quantum-Safe 2FA Works

### Our Enhanced Process:

#### 1. **Quantum-Safe Code Generation**
Instead of HMAC-SHA1, we use **SHAKE-256**:
- **SHAKE-256**: A quantum-resistant hash function
- **Variable Output**: Can produce any length of secure randomness
- **Future-Proof**: Even quantum computers can't reverse it

```
Traditional: HMAC-SHA1(secret, time) → 6-digit code
PQC Version: SHAKE-256(secret, time) → 6-digit code + signature
```

#### 2. **Cryptographic Signatures**
Each code comes with a **Dilithium signature**:
- **What it does**: Mathematically proves the code is authentic
- **Quantum-Safe**: Uses lattice-based cryptography
- **Unforgeable**: Impossible to fake, even with quantum computers

#### 3. **Automatic Key Rotation**
Unlike traditional 2FA where keys never change:
- **Kyber Key Exchange**: Quantum-safe method to create new keys
- **24-Hour Rotation**: New encryption keys every day
- **Forward Secrecy**: If today's key is compromised, yesterday's data stays safe

---

## Core Technologies Explained

### 1. SHAKE-256 (Hash Function)
**What it is**: A cryptographic function that turns any input into secure random output

**Simple Analogy**: Imagine a magic blender that:
- Takes any ingredients (your secret + time)
- Always produces the same smoothie for the same ingredients
- But you can never figure out the ingredients from the smoothie
- Even with a quantum-powered reverse-blender

**Technical Details**:
```go
// Traditional approach (vulnerable)
code := HMAC_SHA1(secret, timeSlot)

// Our quantum-safe approach
shake := NewSHAKE256()
shake.Write(secret)
shake.Write(timeSlot)
code := shake.Read(6_digits_worth)
```

### 2. Dilithium Signatures
**What it is**: A way to create unforgeable digital signatures that quantum computers can't break

**Simple Analogy**: Think of it like a quantum-proof notary stamp:
- Only you can create your unique stamp
- Anyone can verify it's really yours
- Even quantum computers can't forge your stamp
- Based on solving really hard math problems (lattices)

**How it works**:
1. Generate a special key pair (public + private)
2. Use private key to "sign" each TOTP code
3. Others use public key to verify the signature is real
4. The math is based on problems quantum computers struggle with

### 3. Kyber Key Exchange
**What it is**: A quantum-safe way for two parties to agree on a secret key

**Simple Analogy**: Imagine you and a friend want to agree on a secret password while talking in a crowded room:
- Traditional method: Like whispering (quantum computers have super hearing)
- Kyber method: Like using a quantum-proof code language

**Process**:
1. **Key Generation**: Create quantum-safe key pairs
2. **Encapsulation**: Wrap the secret in quantum-proof packaging
3. **Decapsulation**: Only the intended recipient can unwrap it
4. **Shared Secret**: Both parties now have the same secret key

---

## System Architecture

### High-Level Components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Mobile App    │    │   API Server    │    │   Database      │
│                 │    │                 │    │                 │
│ • Generate TOTP │◄──►│ • Verify Codes  │◄──►│ • User Data     │
│ • Store Keys    │    │ • Rotate Keys   │    │ • Audit Logs    │
│ • Sign Codes    │    │ • Business API  │    │ • Key History   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Data Flow:

1. **User Registration**:
   ```
   User → Server: Create account
   Server → Server: Generate quantum-safe keypair
   Server → Database: Store encrypted keys
   Server → User: Return QR code with secret
   ```

2. **Code Generation**:
   ```
   App: secret + time → SHAKE-256 → code
   App: code + private_key → Dilithium → signature
   App → User: Display "123456" + signature
   ```

3. **Code Verification**:
   ```
   User → Server: code + signature
   Server: Regenerate expected code using SHAKE-256
   Server: Verify signature using Dilithium public key
   Server: Compare codes + validate signature
   Server → User: ✅ Access granted or ❌ Access denied
   ```

### Database Schema Highlights:

```sql
-- User cryptographic keys
CREATE TABLE user_keypairs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,    -- Dilithium public key
    private_key TEXT NOT NULL,   -- Encrypted Dilithium private key
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME,
    expires_at DATETIME         -- For key rotation
);

-- TOTP account configurations  
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    secret_key TEXT NOT NULL,   -- Encrypted TOTP secret
    algorithm TEXT DEFAULT 'SHAKE256',
    digits INTEGER DEFAULT 6,
    period INTEGER DEFAULT 30
);

-- Key rotation history
CREATE TABLE key_rotations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    old_key_id TEXT,
    new_key_id TEXT NOT NULL,
    rotation_type TEXT,        -- 'scheduled', 'forced', 'emergency'
    rotation_date DATETIME
);
```

---

## Security Features

### 1. **Rate Limiting**
**What it does**: Prevents brute force attacks

**How it works**:
- Maximum 10 login attempts per minute per IP
- Maximum 20 TOTP verifications per minute per user
- Exponential backoff for repeated failures

```go
// Example rate limiting logic
func (rl *RateLimiter) Allow(key string) bool {
    limiter := rl.getLimiter(key)
    return limiter.Allow() // Uses token bucket algorithm
}
```

### 2. **Audit Logging**
**What it does**: Records every security-relevant action

**Example logs**:
```json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "user_id": "user123",
    "action": "totp_verified",
    "result": "success",
    "ip_address": "192.168.1.100",
    "details": {
        "account_id": "acc456",
        "service_name": "GitHub",
        "has_signature": true
    }
}
```

### 3. **Input Validation**
**What it does**: Prevents injection attacks and malformed data

**Examples**:
- Email validation with regex patterns
- Password strength requirements (8+ chars, mixed case, numbers, symbols)
- UUID format validation for all IDs
- SQL injection prevention through prepared statements

### 4. **Encryption at Rest**
**What it does**: Protects stored data even if database is compromised

**How it works**:
- All sensitive data encrypted with AES-256-GCM
- Encryption keys derived from master secret using SHAKE-256
- Different encryption keys for different data types

```go
// Example encryption
func EncryptData(data []byte, key string) (string, error) {
    keyBytes := SHAKE256([]byte(key), 32)  // Derive 256-bit key
    
    block, _ := aes.NewCipher(keyBytes)
    gcm, _ := cipher.NewGCM(block)
    
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}
```

---

## Business Integration

### RESTful API Design

#### 1. **User Management**
```http
POST /api/v1/auth/register
Content-Type: application/json

{
    "username": "john_doe",
    "email": "john@company.com", 
    "password": "SecureP@ssw0rd123"
}

Response:
{
    "id": "user123",
    "username": "john_doe",
    "email": "john@company.com",
    "created_at": "2024-01-15T10:30:00Z"
}
```

#### 2. **TOTP Operations**
```http
POST /api/v1/totp/generate
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "account_id": "acc456"
}

Response:
{
    "code": "123456",
    "signature": "MEUCIQDxyz...",  // Dilithium signature
    "expires_at": 1705320630,      // Unix timestamp
    "period": 30,
    "time_sync": 1705320600        // Server time for sync
}
```

#### 3. **Business API**
```http
POST /api/business/v1/verify
X-API-Key: pqc_business_key_abc123
Content-Type: application/json

{
    "user_id": "user123", 
    "code": "123456"
}

Response:
{
    "valid": true,
    "user_id": "user123",
    "verified_at": 1705320600
}
```

### Webhook Integration

Businesses can receive real-time notifications:

```http
POST https://your-company.com/webhook
Content-Type: application/json
X-PQC-Signature: sha256=abc123...

{
    "event": "totp_verified",
    "timestamp": 1705320600,
    "data": {
        "user_id": "user123",
        "external_user_id": "employee_456",
        "result": "success",
        "service_name": "GitHub"
    }
}
```

### Analytics Dashboard

Real-time metrics available via API:

```json
{
    "total_users": 1250,
    "active_users": 1100,
    "total_verifications": 45000,
    "success_rate": 99.2,
    "daily_stats": [
        {
            "date": "2024-01-15",
            "requests": 2500,
            "successes": 2480,
            "success_rate": 99.2
        }
    ]
}
```

---

## Real-World Example

Let's walk through a complete scenario where Sarah uses PQC Authenticator to log into her company's GitHub account.

### Setup Phase (One-time)

1. **Sarah's IT Admin Sets Up Business Account**:
   ```bash
   curl -X POST https://pqc-auth.company.com/api/business/v1/register \
     -H "Content-Type: application/json" \
     -d '{
       "company_name": "TechCorp Inc",
       "contact_email": "admin@techcorp.com",
       "plan": "enterprise"
     }'
   
   # Returns API key: pqc_k8sH3mP9qR7wX2nF...
   ```

2. **Sarah Registers Her Account**:
   ```bash
   curl -X POST https://pqc-auth.company.com/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "sarah_dev",
       "email": "sarah@techcorp.com",
       "password": "MySecure2024Pass!"
     }'
   ```

3. **Sarah Adds GitHub to Her Accounts**:
   - Opens PQC Authenticator app
   - Taps "Add Account"
   - Enters: Service="GitHub", Issuer="TechCorp"
   - App generates quantum-safe secret key
   - App shows QR code to scan into GitHub

4. **Behind the scenes**:
   ```go
   // Generate secret key using quantum-safe random
   secretKey := generateRandomBytes(32)
   
   // Encrypt it before storing
   encryptedSecret := encryptData(secretKey, userEncryptionKey)
   
   // Store in database
   account := Account{
       UserID:      "sarah123",
       ServiceName: "GitHub", 
       SecretKey:   encryptedSecret,
       Algorithm:   "SHAKE256",
       Digits:      6,
       Period:      30,
   }
   ```

### Daily Usage

**Morning - Sarah Logs into GitHub**:

1. **GitHub asks for 2FA code**

2. **Sarah opens PQC Authenticator**:
   - App retrieves encrypted secret from local storage
   - App decrypts secret using her device key
   - App generates code:
   ```go
   currentTime := time.Now().Unix() / 30  // 30-second period
   
   // Quantum-safe code generation
   shake := NewSHAKE256()
   shake.Write(secretKey)
   shake.Write(currentTime)
   code := shake.Read(6) // "234567"
   
   // Generate signature for authenticity
   signature := dilithiumSign(privateKey, code + userID)
   ```

3. **App displays**: `234567` (with invisible signature)

4. **Sarah enters code into GitHub**

5. **GitHub's system verifies**:
   ```bash
   curl -X POST https://pqc-auth.company.com/api/business/v1/verify \
     -H "X-API-Key: pqc_k8sH3mP9qR7wX2nF..." \
     -H "Content-Type: application/json" \
     -d '{
       "user_id": "sarah123",
       "code": "234567"
     }'
   
   # Response: {"valid": true, "verified_at": 1705320600}
   ```

6. **PQC Server verification process**:
   ```go
   // Retrieve Sarah's account
   account := getAccountByUserID("sarah123", "GitHub")
   
   // Decrypt secret key
   secretKey := decryptData(account.SecretKey, serverEncryptionKey)
   
   // Regenerate expected code
   expectedCode := generateTOTPCode(secretKey, currentTime)
   
   // Verify code matches
   if expectedCode == "234567" {
       // Success! Log the event and return true
       logAuditEvent("totp_verified", "success", sarah, github)
       return true
   }
   ```

7. **GitHub grants access** ✅

### Key Rotation (Automatic)

**That night at 2 AM**:

1. **Automatic key rotation triggers**:
   ```go
   // System automatically rotates Sarah's keys
   oldKeypair := getCurrentKeypair("sarah123")
   
   // Generate new quantum-safe keypair
   newPublicKey, newPrivateKey := generateDilithiumKeypair()
   
   // Create new keypair record
   newKeypair := UserKeypair{
       UserID:     "sarah123",
       PublicKey:  newPublicKey,
       PrivateKey: encrypt(newPrivateKey, masterKey),
       IsActive:   true,
   }
   
   // Deactivate old keypair
   oldKeypair.IsActive = false
   oldKeypair.ExpiresAt = time.Now().Add(48 * time.Hour)
   ```

2. **Forward secrecy achieved**: Even if today's keys are compromised, yesterday's TOTP codes remain secure.

### Monthly Analytics Report

**IT Admin Reviews Security**:
```bash
curl -X GET https://pqc-auth.company.com/api/business/v1/analytics?days=30 \
  -H "X-API-Key: pqc_k8sH3mP9qR7wX2nF..."
```

**Response shows**:
- Total authentications: 15,247
- Success rate: 99.8%
- Failed attempts: 31 (all from known phishing attempts)
- Key rotations: 124 (automatic)
- Most active services: GitHub (45%), Slack (30%), AWS (25%)

---

## Why This Matters

### For Individuals:
- **Future-proof security**: Your accounts stay safe even when quantum computers arrive
- **Better user experience**: Faster, more reliable than SMS codes
- **Backup and recovery**: Encrypted backups protect against device loss
- **Multi-device support**: Sync across phones, tablets, computers

### For Businesses:
- **Regulatory compliance**: Meet future post-quantum security requirements
- **Zero-trust architecture**: Cryptographically verify every authentication
- **Audit trails**: Complete visibility into access patterns
- **API integration**: Seamlessly integrate with existing systems
- **Cost savings**: Reduce support tickets from SMS delivery issues

### For Society:
- **Economic protection**: Prevent massive breaches when quantum computers arrive
- **Critical infrastructure**: Protect power grids, hospitals, financial systems
- **Privacy preservation**: Keep personal data secure in quantum era
- **Innovation enablement**: Build quantum-safe systems from the ground up

### The Timeline:
- **2024**: Deploy PQC systems (like this one)
- **2025-2030**: Quantum computers improve rapidly
- **2030-2035**: Quantum computers threaten current encryption
- **2035+**: Only PQC-protected systems remain secure

### Investment Protection:
By adopting PQC Authenticator now:
- **No migration needed**: System already quantum-safe
- **Gradual rollout**: Replace current 2FA systems over time
- **Lower risk**: Avoid emergency migrations under pressure
- **Competitive advantage**: First-mover advantage in quantum-safe security

---

## Technical Deep Dive: Code Examples

### TOTP Generation with SHAKE-256

```go
package auth

import (
    "encoding/binary"
    "golang.org/x/crypto/sha3"
    "math"
    "time"
)

type PQTOTP struct {
    secret []byte
    digits int
    period int
}

func NewPQTOTP(secret []byte, digits, period int) *PQTOTP {
    return &PQTOTP{
        secret: secret,
        digits: digits,
        period: period,
    }
}

func (pq *PQTOTP) GenerateCode(timestamp time.Time) (string, error) {
    // Calculate time counter
    counter := uint64(timestamp.Unix()) / uint64(pq.period)
    
    // Create SHAKE-256 instance
    shake := sha3.NewShake256()
    
    // Add secret key
    shake.Write(pq.secret)
    
    // Add time counter
    counterBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(counterBytes, counter)
    shake.Write(counterBytes)
    
    // Extract hash bytes
    hashBytes := make([]byte, 32)
    shake.Read(hashBytes)
    
    // Dynamic truncation (same as RFC 6238)
    offset := hashBytes[len(hashBytes)-1] & 0x0F
    code := binary.BigEndian.Uint32(hashBytes[offset:offset+4]) & 0x7FFFFFFF
    
    // Reduce to desired digits
    mod := uint32(math.Pow10(pq.digits))
    code = code % mod
    
    // Format with leading zeros
    format := fmt.Sprintf("%%0%dd", pq.digits)
    return fmt.Sprintf(format, code), nil
}
```

### Dilithium Signature Generation

```go
package crypto

import (
    "github.com/cloudflare/circl/sign/dilithium/mode3"
    "encoding/base64"
)

type DilithiumSigner struct {
    privateKey mode3.PrivateKey
    publicKey  mode3.PublicKey
}

func NewDilithiumSigner() (*DilithiumSigner, error) {
    // Generate quantum-safe keypair
    publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }
    
    return &DilithiumSigner{
        privateKey: *privateKey,
        publicKey:  *publicKey,
    }, nil
}

func (ds *DilithiumSigner) Sign(message []byte) (string, error) {
    // Create signature
    signature := make([]byte, mode3.SignatureSize)
    mode3.SignTo(&ds.privateKey, message, signature)
    
    // Return base64 encoded
    return base64.StdEncoding.EncodeToString(signature), nil
}

func (ds *DilithiumSigner) Verify(message []byte, signatureB64 string) (bool, error) {
    // Decode signature
    signature, err := base64.StdEncoding.DecodeString(signatureB64)
    if err != nil {
        return false, err
    }
    
    // Verify signature
    return mode3.Verify(&ds.publicKey, message, signature), nil
}
```

### Key Rotation with Kyber

```go
package crypto

import (
    "github.com/cloudflare/circl/kem/kyber/kyber768"
    "crypto/rand"
)

func RotateKeys(oldPrivateKey []byte) (newPublicKey, newPrivateKey, sharedSecret []byte, err error) {
    // Generate new Kyber keypair
    publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
    if err != nil {
        return nil, nil, nil, err
    }
    
    // Serialize keys
    newPublicKeyBytes, _ := publicKey.MarshalBinary()
    newPrivateKeyBytes, _ := privateKey.MarshalBinary()
    
    // Generate shared secret for secure key transition
    ciphertext := make([]byte, kyber768.CiphertextSize)
    sharedSecret = make([]byte, kyber768.SharedKeySize)
    seed := make([]byte, kyber768.EncapsulationSeedSize)
    rand.Read(seed)
    
    publicKey.EncapsulateTo(ciphertext, sharedSecret, seed)
    
    return newPublicKeyBytes, newPrivateKeyBytes, sharedSecret, nil
}
```

This system represents the cutting edge of authentication security, protecting against both current threats and future quantum attacks. By understanding these concepts, you can appreciate why PQC Authenticator isn't just another 2FA app—it's a critical piece of infrastructure for the quantum computing era.