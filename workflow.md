# PQC Authenticator Workflow Documentation

## Table of Contents
1. [User Registration Workflow](#user-registration-workflow)
2. [Device Registration Workflow](#device-registration-workflow)
3. [Account Setup Workflow](#account-setup-workflow)
4. [TOTP Generation Workflow](#totp-generation-workflow)
5. [TOTP Verification Workflow](#totp-verification-workflow)
6. [Business Integration Workflow](#business-integration-workflow)
7. [Key Rotation Workflow](#key-rotation-workflow)
8. [Backup and Recovery Workflow](#backup-and-recovery-workflow)
9. [Business User Provisioning Workflow](#business-user-provisioning-workflow)
10. [Audit and Analytics Workflow](#audit-and-analytics-workflow)

---

## User Registration Workflow

### Overview
This workflow describes how a new user creates an account in the PQC Authenticator system.

### Entities Involved
- **User**: Person wanting to register
- **Frontend Application**: Mobile app or web interface
- **API Server**: Backend authentication server
- **Database**: SQLite database storing user data
- **Key Manager**: Cryptographic key management system
- **Logger**: Audit logging system

### Detailed Process Flow

#### Step 1: User Initiates Registration
**Actor**: User
**Action**: Opens application and clicks "Sign Up"
**Input**: None
**Output**: Registration form displayed

#### Step 2: User Provides Information
**Actor**: User
**Action**: Fills out registration form
**Input**: 
- Username (3-50 characters, alphanumeric + underscore/dash)
- Email address (valid email format)
- Password (minimum 8 characters, must include uppercase, lowercase, number, special character)
**Output**: Form data ready for submission

#### Step 3: Frontend Validates Input
**Actor**: Frontend Application
**Action**: Client-side validation of user input
**Process**:
1. Check username length and character requirements
2. Validate email format using regex
3. Check password strength requirements
4. Ensure all required fields are filled
**Decision Point**: If validation fails → Show error messages and return to Step 2
**Output**: Validated form data ready for API call

#### Step 4: API Request Sent
**Actor**: Frontend Application
**Action**: Sends HTTP POST request to registration endpoint
**Request Details**:
- Endpoint: `POST /api/v1/auth/register`
- Headers: `Content-Type: application/json`
- Body: JSON with username, email, password
**Output**: HTTP request transmitted to server

#### Step 5: Server Receives and Validates Request
**Actor**: API Server
**Action**: Processes incoming registration request
**Process**:
1. Parse JSON request body
2. Apply rate limiting (check if IP has exceeded registration attempts)
3. Validate request format and required fields
4. Apply server-side input validation and sanitization
**Decision Point**: If validation fails → Return HTTP 400 with error details
**Output**: Validated request data ready for processing

#### Step 6: Check for Existing Users
**Actor**: API Server
**Action**: Query database to check for duplicates
**Process**:
1. Query users table for existing username
2. Query users table for existing email address
**Decision Point**: 
- If username exists → Return HTTP 409 "Username already exists"
- If email exists → Return HTTP 409 "Email already registered"
**Output**: Confirmation that user data is unique

#### Step 7: Hash Password
**Actor**: API Server
**Action**: Securely hash the user's password
**Process**:
1. Generate 32-byte random salt using crypto/rand
2. Apply Argon2id hashing with parameters:
   - Time cost: 3 iterations
   - Memory cost: 64MB
   - Parallelism: 4 threads
   - Output length: 32 bytes
3. Combine salt + hash for storage
**Output**: Secure password hash ready for database storage

#### Step 8: Create User Record
**Actor**: API Server
**Action**: Generate user record with metadata
**Process**:
1. Generate unique UUID for user ID
2. Set current timestamp for created_at and updated_at
3. Set is_active to true
4. Initialize failed_login_attempts to 0
5. Set locked_until to null
**Output**: Complete user record ready for database insertion

#### Step 9: Begin Database Transaction
**Actor**: Database
**Action**: Start atomic transaction for user creation
**Purpose**: Ensure either complete success or complete rollback
**Output**: Transaction context established

#### Step 10: Insert User into Database
**Actor**: API Server
**Action**: Execute INSERT query for users table
**Process**:
1. Prepare SQL statement with parameterized query
2. Execute INSERT with user data
3. Check for any database constraints violations
**Decision Point**: If database error → Rollback transaction and return HTTP 500
**Output**: User record successfully inserted

#### Step 11: Generate Cryptographic Keypair
**Actor**: Key Manager
**Action**: Create Dilithium quantum-safe keypair for user
**Process**:
1. Use Dilithium Mode3 to generate key pair
2. Public key: Used for signature verification
3. Private key: Used for signing TOTP codes
4. Encode keys in base64 format for storage
**Output**: Quantum-safe cryptographic keypair

#### Step 12: Encrypt Private Key
**Actor**: Key Manager
**Action**: Encrypt private key before database storage
**Process**:
1. Retrieve master encryption key from configuration
2. Generate random nonce for AES-GCM encryption
3. Encrypt private key using AES-256-GCM
4. Combine nonce + ciphertext for storage
**Output**: Encrypted private key safe for database storage

#### Step 13: Store Keypair in Database
**Actor**: API Server
**Action**: Insert keypair record into user_keypairs table
**Process**:
1. Generate unique UUID for keypair ID
2. Associate with user ID
3. Store public key in plaintext (it's public)
4. Store encrypted private key
5. Set is_active to true
6. Set key_version to 1
7. Set algorithm to "dilithium-mode3"
**Decision Point**: If database error → Rollback entire transaction
**Output**: Keypair record successfully stored

#### Step 14: Commit Transaction
**Actor**: Database
**Action**: Commit all changes atomically
**Process**:
1. Finalize user record insertion
2. Finalize keypair record insertion
3. Make all changes permanent
**Decision Point**: If commit fails → Return HTTP 500 error
**Output**: User successfully created in system

#### Step 15: Log Audit Event
**Actor**: Logger
**Action**: Record user registration in audit logs
**Process**:
1. Generate audit log entry with:
   - Event type: "user_registered"
   - User ID: newly created user ID
   - Timestamp: current time
   - IP address: from request headers
   - User agent: from request headers
   - Result: "success"
2. Insert into audit_logs table
**Output**: Registration event permanently logged

#### Step 16: Generate Response
**Actor**: API Server
**Action**: Create successful registration response
**Process**:
1. Create response object with:
   - User ID
   - Username
   - Email
   - Created timestamp
2. Exclude sensitive data (password hash, private keys)
3. Set HTTP status 201 (Created)
**Output**: JSON response ready to send

#### Step 17: Send Response to Frontend
**Actor**: API Server
**Action**: Transmit HTTP response to frontend
**Response Format**:
- Status: 201 Created
- Body: JSON with user details
**Output**: Response transmitted to frontend

#### Step 18: Frontend Processes Response
**Actor**: Frontend Application
**Action**: Handle successful registration response
**Process**:
1. Parse JSON response
2. Extract user information
3. Show success message to user
4. Navigate to login screen or dashboard
**Output**: User notified of successful registration

#### Step 19: User Sees Confirmation
**Actor**: User
**Action**: Views registration success message
**Process**:
1. See confirmation that account was created
2. Optionally receive email confirmation (if implemented)
3. Proceed to log in with new credentials
**Output**: User ready to use the system

### Error Handling Scenarios

#### Scenario A: Invalid Input Data
**Trigger**: User provides invalid username, email, or weak password
**Process**:
1. Frontend validation catches most issues immediately
2. Server validation provides detailed error messages
3. User receives specific guidance on fixing issues
4. No database changes occur
**Resolution**: User corrects input and retries

#### Scenario B: Username/Email Already Exists
**Trigger**: User tries to register with existing credentials
**Process**:
1. Database query reveals existing record
2. Server returns HTTP 409 Conflict with specific message
3. User informed about which field conflicts
4. No new records created
**Resolution**: User chooses different username/email

#### Scenario C: Database Transaction Failure
**Trigger**: Database error during user or keypair creation
**Process**:
1. Transaction automatically rolls back
2. No partial data left in database
3. Error logged for investigation
4. User receives generic "registration failed" message
**Resolution**: User can retry; admin investigates logs

#### Scenario D: Cryptographic Key Generation Failure
**Trigger**: Random number generation or cryptographic operation fails
**Process**:
1. Key generation process fails before database insertion
2. Transaction rolls back completely
3. Security-related error logged immediately
4. System health check triggered
**Resolution**: System administrator investigates security subsystem

### Success Criteria
- User record exists in database with correct data
- Password is securely hashed and stored
- Quantum-safe keypair generated and stored
- All operations logged for audit
- User can immediately proceed to login
- No sensitive data exposed in responses or logs

### Performance Expectations
- Total workflow completion: < 2 seconds
- Database operations: < 500ms
- Cryptographic operations: < 1 second
- Network round trip: < 200ms
- Frontend processing: < 100ms

---

## Device Registration Workflow

### Overview
This workflow describes how users register trusted devices for enhanced security and device-specific authentication.

### Entities Involved
- **User**: Authenticated user registering a device
- **Device**: Mobile phone, tablet, or computer being registered
- **Frontend Application**: PQC Authenticator app on the device
- **API Server**: Backend server handling device registration
- **Device Manager**: Service managing device fingerprinting and keys
- **Database**: Storage for device records and keys

### Detailed Process Flow

#### Step 1: User Initiates Device Registration
**Actor**: User
**Action**: Opens "Add Device" in authenticated app
**Preconditions**: User must be logged in with valid JWT token
**Process**:
1. User navigates to device management section
2. Clicks "Register This Device" or "Add New Device"
3. System checks authentication status
**Decision Point**: If not authenticated → Redirect to login
**Output**: Device registration form displayed

#### Step 2: Device Fingerprint Generation
**Actor**: Frontend Application
**Action**: Generate unique device identifier
**Process**:
1. Collect device characteristics:
   - Hardware model and manufacturer
   - Operating system version
   - Screen resolution and density
   - Available sensors list
   - Network MAC address (if available)
   - Device timezone and locale
2. Create fingerprint hash using SHAKE-256
3. Store fingerprint locally for future use
**Output**: Unique device fingerprint string

#### Step 3: Generate Device-Specific Keypair
**Actor**: Frontend Application
**Action**: Create Dilithium keypair for this device
**Process**:
1. Use device's secure random number generator
2. Generate Dilithium Mode3 keypair locally
3. Store private key in device's secure storage (Keychain/Keystore)
4. Prepare public key for transmission to server
**Security Note**: Private key never leaves the device
**Output**: Device-specific public/private keypair

#### Step 4: User Provides Device Information
**Actor**: User
**Action**: Fills device registration form
**Input Required**:
- Device name (user-friendly name like "John's iPhone")
- Device type (phone, tablet, computer, etc.)
- Optional description
**Validation**:
- Name: 1-100 characters
- Type: Must be from predefined list
**Output**: Device metadata ready for submission

#### Step 5: Prepare Registration Request
**Actor**: Frontend Application
**Action**: Assemble device registration data
**Request Data**:
- Device name (from user input)
- Device fingerprint (generated in Step 2)
- Public key (from Step 3)
- Device type and OS information
- Current IP address and user agent
**Security**: All data signed with device private key
**Output**: Complete registration request package

#### Step 6: Send Registration Request
**Actor**: Frontend Application
**Action**: Submit HTTP POST request to device registration endpoint
**Request Details**:
- Endpoint: `POST /api/v1/devices/register`
- Headers: 
  - `Authorization: Bearer <jwt_token>`
  - `Content-Type: application/json`
- Body: JSON with device registration data
**Output**: HTTP request sent to server

#### Step 7: Server Authenticates Request
**Actor**: API Server
**Action**: Validate user authentication and authorization
**Process**:
1. Extract JWT token from Authorization header
2. Verify token signature and expiration
3. Extract user ID from token claims
4. Check user account status (active, not locked)
**Decision Point**: If authentication fails → Return HTTP 401
**Output**: Authenticated user context established

#### Step 8: Validate Device Registration Data
**Actor**: API Server
**Action**: Perform server-side validation
**Validation Checks**:
1. Device name length and characters
2. Device fingerprint format and uniqueness
3. Public key format and validity
4. Device type from allowed list
5. Rate limiting (max devices per user per hour)
**Decision Point**: If validation fails → Return HTTP 400 with details
**Output**: Validated device registration data

#### Step 9: Check Device Limits
**Actor**: API Server
**Action**: Verify user hasn't exceeded device limits
**Process**:
1. Count existing active devices for user
2. Check against plan limits (basic: 3, pro: 10, enterprise: unlimited)
3. Optionally check for suspicious registration patterns
**Decision Point**: If limit exceeded → Return HTTP 403 with upgrade suggestion
**Output**: Confirmation that device can be registered

#### Step 10: Check for Existing Device
**Actor**: API Server
**Action**: Query database for existing device with same fingerprint
**Process**:
1. Search devices table for matching user_id + device_fingerprint
2. If found, check if it's active or inactive
**Decision Points**:
- If active device exists → Return HTTP 409 "Device already registered"
- If inactive device exists → Reactivate existing device record
- If no device exists → Proceed with new registration
**Output**: Decision on whether to create new or reactivate existing

#### Step 11: Generate Device Record
**Actor**: API Server
**Action**: Create device database record
**Process**:
1. Generate unique UUID for device ID
2. Associate with authenticated user ID
3. Store device name and type
4. Store device fingerprint
5. Store public key for future verification
6. Set timestamps (created_at, last_used)
7. Set is_active to true
8. Record IP address and user agent
**Output**: Complete device record ready for database

#### Step 12: Store Device in Database
**Actor**: API Server
**Action**: Insert device record into database
**Process**:
1. Begin database transaction
2. Execute INSERT into devices table
3. Check for any constraint violations
**Decision Point**: If database error → Rollback and return HTTP 500
**Output**: Device successfully stored in database

#### Step 13: Log Device Registration
**Actor**: API Server
**Action**: Create audit log entry
**Audit Information**:
- Event: "device_registered"
- User ID: device owner
- Device ID: newly created device ID
- Device name and type
- IP address and user agent
- Timestamp and result status
**Output**: Device registration event logged

#### Step 14: Update User Session
**Actor**: API Server
**Action**: Associate current session with registered device
**Process**:
1. Update session record with device_id
2. Mark session as device-verified
3. Update session activity timestamp
**Output**: Session linked to trusted device

#### Step 15: Generate Success Response
**Actor**: API Server
**Action**: Create device registration response
**Response Data**:
- Device ID (UUID)
- Device name
- Registration timestamp
- Device status (active)
- Success confirmation message
**Security**: No sensitive data included
**Output**: JSON response ready for transmission

#### Step 16: Send Response to Device
**Actor**: API Server
**Action**: Transmit HTTP response
**Response Format**:
- Status: 201 Created
- Body: JSON with device details
**Output**: Response sent to device

#### Step 17: Device Processes Response
**Actor**: Frontend Application
**Action**: Handle successful registration response
**Process**:
1. Parse response JSON
2. Store device ID locally for future reference
3. Update local device status to "registered"
4. Optionally store server-provided device metadata
**Output**: Device locally marked as registered

#### Step 18: User Confirmation
**Actor**: User
**Action**: Views device registration success
**Process**:
1. See confirmation message "Device registered successfully"
2. View device in device management list
3. Receive explanation of enhanced security benefits
**Output**: User informed of successful device registration

### Enhanced Security Features

#### Device Trust Scoring
**Process**: Each device registration includes trust score calculation
**Factors**:
- First-time vs returning device fingerprint
- Geographic location consistency
- Registration time patterns
- Associated user behavior history
**Output**: Trust score affects authentication requirements

#### Device Key Rotation
**Trigger**: Automatic monthly rotation for high-security accounts
**Process**:
1. Device generates new keypair locally
2. Signs rotation request with old private key
3. Server validates signature and updates public key
4. Old keys marked for deletion after grace period
**Output**: Fresh cryptographic keys for continued security

#### Suspicious Device Detection
**Monitors**:
- Multiple devices with similar fingerprints
- Rapid device registrations from same IP
- Device registrations from unusual locations
- Fingerprint manipulation attempts
**Actions**:
- Additional verification requirements
- Account owner notifications
- Temporary registration blocks
- Enhanced audit logging

### Error Recovery Scenarios

#### Network Failure During Registration
**Situation**: Connection lost during device registration
**Recovery**:
1. Frontend retains generated keypair and fingerprint
2. Automatic retry with same data maintains consistency
3. Server handles duplicate registration gracefully
4. User sees seamless recovery experience

#### Device Fingerprint Collision
**Situation**: Two devices generate identical fingerprints
**Recovery**:
1. Server detects fingerprint collision
2. Requests additional entropy from device
3. New fingerprint generated with extra randomness
4. Registration proceeds with unique identifier

#### Database Corruption During Registration
**Situation**: Device record partially written due to system failure
**Recovery**:
1. Transaction rollback prevents partial records
2. Device can safely retry registration
3. Audit logs help identify and resolve issues
4. System health checks detect and report problems

### Success Criteria
- Device record exists with correct associations
- Device keypair properly generated and stored
- User can authenticate from registered device
- Device appears in user's device management interface
- All operations properly audited and logged
- Enhanced security features activated for device

### Performance Expectations
- Device fingerprint generation: < 1 second
- Keypair generation: < 2 seconds
- Network registration request: < 1 second
- Database operations: < 500ms
- Total workflow completion: < 5 seconds

---

## Account Setup Workflow

### Overview
This workflow describes how users add TOTP accounts (like GitHub, Google, etc.) to their PQC Authenticator for quantum-safe two-factor authentication.

### Entities Involved
- **User**: Person setting up TOTP for a service
- **Target Service**: External service (GitHub, Google, etc.) requiring 2FA
- **Frontend Application**: PQC Authenticator app
- **API Server**: Backend server managing TOTP accounts
- **Secret Manager**: Service handling TOTP secret generation and encryption
- **QR Generator**: Service creating setup QR codes

### Detailed Process Flow

#### Step 1: User Initiates Account Setup
**Actor**: User
**Action**: Starts adding new TOTP account
**Context**: User wants to enable 2FA on external service
**Process**:
1. User opens PQC Authenticator app
2. Navigates to "Add Account" or taps "+" button
3. Chooses "Manual Entry" or "Scan QR Code" option
**Decision Point**: Manual vs QR code determines next steps
**Output**: Account setup method selected

#### Step 2A: Manual Account Entry (Alternative Path)
**Actor**: User
**Action**: Manually enters account information
**Required Information**:
- Service name (e.g., "GitHub", "Google Workspace")
- Account identifier (username or email)
- Issuer name (organization name)
- Service URL (optional)
**Validation**:
- Service name: 1-100 characters, alphanumeric + spaces
- Issuer: 1-100 characters
- URL: Valid HTTP/HTTPS format if provided
**Output**: Account metadata ready for secret generation

#### Step 2B: QR Code Scanning (Primary Path)
**Actor**: User
**Action**: Scans QR code from target service
**Process**:
1. Target service displays QR code containing:
   - Secret key (base32 encoded)
   - Service name and issuer
   - Algorithm (usually SHA1, will be upgraded)
   - Period and digits configuration
2. User points camera at QR code
3. App decodes QR code and extracts information
**Decision Point**: If QR code invalid → Show error and return to Step 1
**Output**: Account information extracted from QR code

#### Step 3: Validate Account Information
**Actor**: Frontend Application
**Action**: Perform client-side validation
**Validation Rules**:
- Service name: Required, length 1-100 characters
- Issuer: Required, length 1-100 characters
- Secret: Valid base32 format (if from QR code)
- Period: 15-300 seconds (default 30)
- Digits: 6-8 digits (default 6)
**Decision Point**: If validation fails → Show errors and return to Step 2
**Output**: Validated account information

#### Step 4: Generate TOTP Secret (Manual Entry Path)
**Actor**: Secret Manager
**Action**: Generate cryptographically secure TOTP secret
**Process** (only for manual entry, QR codes include secret):
1. Generate 32 bytes of cryptographically secure random data
2. Encode secret in base32 format for compatibility
3. Validate secret meets TOTP standard requirements
**Security**: Uses system's cryptographically secure random generator
**Output**: Base32-encoded TOTP secret key

#### Step 5: Prepare Account Creation Request
**Actor**: Frontend Application
**Action**: Assemble account creation data
**Request Payload**:
- Service name (sanitized user input)
- Service URL (validated URL or empty)
- Issuer name (sanitized user input)
- TOTP secret (from QR code or generated)
- Algorithm: Always set to "SHAKE256" (quantum-safe upgrade)
- Digits: User preference or default (6)
- Period: User preference or default (30 seconds)
**Security**: Secret encrypted before transmission using session key
**Output**: Complete account creation request

#### Step 6: Send Account Creation Request
**Actor**: Frontend Application
**Action**: Submit HTTP POST to account creation endpoint
**Request Details**:
- Endpoint: `POST /api/v1/accounts`
- Headers:
  - `Authorization: Bearer <jwt_token>`
  - `Content-Type: application/json`
- Body: JSON with account information
**Security**: Request signed with device key for integrity
**Output**: HTTP request transmitted to server

#### Step 7: Server Authenticates Request
**Actor**: API Server
**Action**: Validate user authentication and authorization
**Process**:
1. Extract and validate JWT token
2. Verify token signature using server secret
3. Check token expiration and user status
4. Extract user ID from token claims
**Decision Point**: If authentication fails → Return HTTP 401
**Output**: Authenticated user context established

#### Step 8: Validate Account Data
**Actor**: API Server
**Action**: Perform comprehensive server-side validation
**Validation Checks**:
1. Service name: Length, characters, profanity filter
2. Issuer: Length, characters, business name validation
3. Service URL: Valid format, domain validation, security check
4. TOTP parameters: Period (15-300s), digits (6-8)
5. Secret: Valid base32, proper length, randomness check
**Decision Point**: If validation fails → Return HTTP 400 with specific errors
**Output**: Validated and sanitized account data

#### Step 9: Check for Duplicate Accounts
**Actor**: API Server
**Action**: Verify user doesn't have conflicting account
**Process**:
1. Query accounts table for existing service_name + user_id combination
2. Check for similar service names (fuzzy matching)
3. Optionally warn about potential duplicates
**Decision Points**:
- If exact duplicate → Return HTTP 409 "Account already exists"
- If similar → Return warning but allow creation
**Output**: Confirmation that account can be created

#### Step 10: Encrypt TOTP Secret
**Actor**: Secret Manager
**Action**: Encrypt secret before database storage
**Process**:
1. Retrieve user's encryption key from secure configuration
2. Generate random nonce for AES-GCM encryption
3. Encrypt TOTP secret using AES-256-GCM
4. Combine nonce + ciphertext for storage
5. Securely wipe plaintext secret from memory
**Security**: Secret never stored in plaintext
**Output**: Encrypted secret ready for database storage

#### Step 11: Create Account Database Record
**Actor**: API Server
**Action**: Generate complete account record
**Record Fields**:
- ID: Generated UUID
- User ID: From authenticated session
- Service name: Validated user input
- Service URL: Validated URL or empty
- Secret key: Encrypted TOTP secret
- Algorithm: "SHAKE256" (quantum-safe)
- Digits: User preference (6-8)
- Period: User preference (15-300 seconds)
- Issuer: Validated issuer name
- Timestamps: created_at, updated_at
- Status: is_active = true
- Usage tracking: usage_count = 0, last_used = null
**Output**: Complete account record ready for insertion

#### Step 12: Store Account in Database
**Actor**: API Server
**Action**: Insert account into database with transaction
**Process**:
1. Begin database transaction
2. Execute INSERT into accounts table
3. Verify insertion successful and constraints satisfied
4. Check for any foreign key or unique constraint violations
**Decision Point**: If database error → Rollback transaction, return HTTP 500
**Output**: Account successfully stored in database

#### Step 13: Generate QR Code for Setup
**Actor**: QR Generator
**Action**: Create QR code for setting up external service
**Process**:
1. Decrypt TOTP secret temporarily for QR generation
2. Create OTPAUTH URL format:
   - Protocol: otpauth://totp/
   - Label: Issuer:Username format
   - Parameters: secret, issuer, algorithm, digits, period
3. Generate QR code image from URL (256x256 pixels)
4. Encode QR code as base64 for transmission
5. Securely wipe decrypted secret from memory
**Output**: Base64-encoded QR code image

#### Step 14: Test TOTP Generation
**Actor**: API Server
**Action**: Verify TOTP setup is working correctly
**Process**:
1. Generate test TOTP code using current timestamp
2. Verify code format and length
3. Confirm quantum-safe SHAKE-256 algorithm working
4. Validate code would be accepted by verification process
**Decision Point**: If TOTP generation fails → Delete account record, return error
**Output**: Confirmed working TOTP configuration

#### Step 15: Log Account Creation
**Actor**: API Server
**Action**: Create comprehensive audit log entry
**Audit Information**:
- Event type: "account_created"
- User ID: account owner
- Account ID: newly created account
- Service name and issuer
- Configuration: algorithm, digits, period
- IP address and user agent
- Timestamp and result status
- Security level: "quantum_safe"
**Output**: Account creation permanently logged

#### Step 16: Generate Success Response
**Actor**: API Server
**Action**: Create account creation response
**Response Data**:
- Account ID (UUID)
- Service name and issuer
- Algorithm and configuration (digits, period)
- QR code (base64 image)
- Setup instructions
- Test TOTP code for verification
**Security**: No secret key included in response
**Output**: JSON response with account details and setup info

#### Step 17: Send Response to Client
**Actor**: API Server
**Action**: Transmit successful account creation response
**Response Format**:
- Status: 201 Created
- Headers: Content-Type: application/json
- Body: JSON with account information and QR code
**Performance**: Response compressed for faster transmission
**Output**: Response delivered to client application

#### Step 18: Client Processes Response
**Actor**: Frontend Application
**Action**: Handle successful account creation
**Process**:
1. Parse JSON response and extract account details
2. Display QR code for user to scan into external service
3. Show setup instructions specific to the service
4. Store account ID locally for future reference
5. Update local account list with new entry
**Output**: Account setup interface displayed to user

#### Step 19: User Completes External Service Setup
**Actor**: User
**Action**: Configure 2FA on the external service
**Process**:
1. Navigate to 2FA settings on external service (GitHub, Google, etc.)
2. Choose "Authenticator App" option
3. Scan QR code displayed by PQC Authenticator
4. External service validates setup
5. Service may ask for test code to confirm
**Output**: External service 2FA enabled with PQC Authenticator

#### Step 20: Test Code Generation
**Actor**: User
**Action**: Generate and test first TOTP code
**Process**:
1. Return to PQC Authenticator app
2. Tap on newly created account
3. View generated 6-digit code and countdown timer
4. Optionally test code with external service login
**Verification**: Code should work with external service
**Output**: Confirmed working TOTP setup

#### Step 21: Account Setup Complete
**Actor**: User
**Action**: Verify account is working correctly
**Confirmation Steps**:
1. Account appears in main account list
2. TOTP codes generate every 30 seconds
3. External service accepts generated codes
4. Backup QR code saved or printed if desired
**Output**: Fully functional quantum-safe 2FA account

### Advanced Configuration Options

#### Custom TOTP Parameters
**Period Customization**:
- Standard: 30 seconds (most services)
- High security: 15 seconds (faster rotation)
- Low frequency: 60 seconds (some legacy systems)

**Digit Configuration**:
- Standard: 6 digits (99.99% of services)
- Enhanced: 8 digits (higher entropy, some financial services)

**Algorithm Selection**:
- Default: SHAKE-256 (quantum-safe)
- Legacy compatibility: SHA-1 (for older services)
- Future: SHA-3 variants as standards evolve

#### Batch Account Import
**Use Case**: Migrating from other authenticators
**Process**:
1. Export accounts from previous authenticator
2. Upload encrypted account list to PQC Authenticator
3. Decrypt and validate each account
4. Batch create accounts with single transaction
5. Generate consolidated setup report

### Error Handling and Recovery

#### Invalid QR Code Recovery
**Situation**: QR code cannot be decoded or contains invalid data
**Recovery Steps**:
1. Show specific error message about QR code format
2. Offer manual entry option as alternative
3. Provide guidance on generating new QR code from service
4. Include QR code debugging information for support

#### Secret Key Encryption Failure
**Situation**: Cannot encrypt TOTP secret for storage
**Recovery Steps**:
1. Immediately abort account creation process
2. Log security incident for investigation
3. Verify encryption system health
4. Notify user of temporary service unavailability
5. Retry with fresh encryption keys after issue resolved

#### External Service Integration Issues
**Situation**: TOTP codes not accepted by external service
**Troubleshooting Steps**:
1. Verify time synchronization between devices
2. Check TOTP parameters match service requirements
3. Generate multiple codes across time windows
4. Provide service-specific troubleshooting guides
5. Offer re-setup option with fresh secret

### Success Criteria
- Account record exists with correct configuration
- TOTP secret securely encrypted and stored
- QR code generated for external service setup
- User can generate valid TOTP codes
- External service accepts generated codes
- All operations properly audited and logged
- Account appears in user's account list
- Quantum-safe algorithm properly configured

### Performance Expectations
- QR code scanning: < 2 seconds
- Account validation: < 500ms
- Secret encryption: < 200ms
- Database insertion: < 300ms
- QR code generation: < 1 second
- Total workflow completion: < 5 seconds
- TOTP code generation: < 100ms

---

## TOTP Generation Workflow

### Overview
This workflow describes the real-time process of generating quantum-safe TOTP codes when users need to authenticate with external services.

### Entities Involved
- **User**: Person needing authentication code
- **Frontend Application**: PQC Authenticator displaying codes
- **API Server**: Backend generating and signing codes
- **Secret Manager**: Service handling TOTP secret decryption
- **Key Manager**: Service managing cryptographic signatures
- **Time Synchronization Service**: Ensuring accurate timestamps
- **Rate Limiter**: Preventing abuse of code generation

### Detailed Process Flow

#### Step 1: User Requests TOTP Code
**Actor**: User
**Action**: Opens account to view current TOTP code
**Context**: User needs to authenticate with external service
**Process**:
1. User opens PQC Authenticator app
2. Browses to specific account (GitHub, Google, etc.)
3. Taps account to view current code
4. System checks if cached code is still valid
**Decision Point**: If cached code valid and fresh → Display immediately
**Output**: Code generation request initiated

#### Step 2: Validate User Session
**Actor**: Frontend Application
**Action**: Verify user is authenticated
**Process**:
1. Check local JWT token existence and validity
2. Verify token hasn't expired
3. Confirm user session is active
4. Check device registration status
**Decision Point**: If authentication invalid → Redirect to login
**Output**: Authenticated session confirmed

#### Step 3: Apply Rate Limiting
**Actor**: Rate Limiter
**Action**: Check generation frequency limits
**Process**:
1. Identify user and account for rate limiting
2. Check recent generation history
3. Apply limits:
   - Max 100 generations per hour per account
   - Max 10 generations per minute per user
   - Exponential backoff for rapid requests
**Decision Point**: If rate limit exceeded → Return error with retry time
**Output**: Rate limiting passed, generation allowed

#### Step 4: Retrieve Account Information
**Actor**: API Server
**Action**: Fetch account configuration from database
**Process**:
1. Query accounts table using account_id and user_id
2. Verify account is active (is_active = true)
3. Check account ownership matches authenticated user
4. Extract TOTP configuration:
   - Encrypted secret key
   - Algorithm (SHAKE256)
   - Period (30 seconds default)
   - Digits (6 default)
**Decision Point**: If account not found or inactive → Return HTTP 404
**Output**: Account configuration retrieved

#### Step 5: Decrypt TOTP Secret
**Actor**: Secret Manager
**Action**: Decrypt stored TOTP secret for code generation
**Process**:
1. Retrieve user's encryption key from secure configuration
2. Extract nonce from stored encrypted secret
3. Decrypt secret using AES-256-GCM with user's key
4. Validate decrypted secret format and length
5. Load secret into secure memory for processing
**Security**: Secret exists in plaintext only during generation
**Output**: Decrypted TOTP secret ready for use

#### Step 6: Get Synchronized Time
**Actor**: Time Synchronization Service
**Action**: Obtain accurate current timestamp
**Process**:
1. Get current system time in UTC
2. Apply any configured time offset corrections
3. Account for network time protocol (NTP) drift
4. Calculate time slot based on TOTP period:
   - Current timestamp ÷ period (30 seconds)
   - Result truncated to integer (time counter)
**Accuracy**: Time must be accurate within ±30 seconds
**Output**: Current time counter for TOTP calculation

#### Step 7: Generate Quantum-Safe TOTP Code
**Actor**: API Server
**Action**: Generate TOTP using SHAKE-256 algorithm
**Process**:
1. Initialize SHAKE-256 hash function
2. Input TOTP secret key into hash function
3. Convert time counter to 8-byte big-endian format
4. Input time counter bytes into hash function
5. Extract 32 bytes of hash output
6. Apply dynamic truncation:
   - Use last byte as offset indicator
   - Extract 4 bytes starting at offset
   - Convert to 31-bit positive integer
7. Apply modulo operation to get desired digits:
   - Code = (truncated_value % 10^digits)
8. Format with leading zeros to exact digit length
**Algorithm**: SHAKE-256 provides quantum-safe hash function
**Output**: 6-digit TOTP code (e.g., "123456")

#### Step 8: Calculate Code Expiration
**Actor**: API Server
**Action**: Determine when current code expires
**Process**:
1. Calculate current time slot: floor(current_time / period)
2. Calculate next time slot: current_slot + 1
3. Calculate expiration time: next_slot × period
4. Calculate remaining time: expiration_time - current_time
**Output**: Code expiration timestamp and remaining seconds

#### Step 9: Generate Cryptographic Signature
**Actor**: Key Manager
**Action**: Sign TOTP code for authenticity verification
**Process**:
1. Retrieve user's active Dilithium private key
2. Decrypt private key using master encryption key
3. Create message to sign:
   - User ID + ":" + TOTP code + ":" + timestamp
4. Generate Dilithium signature on message
5. Encode signature in base64 format for transmission
6. Securely wipe private key from memory
**Security**: Signature proves code authenticity and origin
**Output**: Base64-encoded Dilithium signature

#### Step 10: Log Generation Event
**Actor**: API Server
**Action**: Record TOTP generation in audit logs
**Audit Information**:
- Event type: "totp_generated"
- User ID: code requester
- Account ID: source account
- Service name: target service
- Timestamp: generation time
- Code validity period: start and end times
- IP address and user agent
- Has signature: true
- Algorithm used: "SHAKE256"
**Output**: Generation event permanently logged

#### Step 11: Update Account Usage Statistics
**Actor**: API Server
**Action**: Track account usage for analytics
**Process**:
1. Increment usage_count for the account
2. Update last_used timestamp to current time
3. Record usage pattern for fraud detection
4. Update user activity timestamp
**Output**: Account usage statistics updated

#### Step 12: Prepare Response Package
**Actor**: API Server
**Action**: Assemble complete TOTP response
**Response Components**:
- TOTP code: 6-digit string
- Signature: Base64 Dilithium signature (optional)
- Expires at: Unix timestamp when code expires
- Period: Code validity period in seconds
- Time sync: Current server time for client sync
- Algorithm: "SHAKE256" for client verification
- Remaining time: Seconds until expiration
**Security**: No secret key included in response
**Output**: Complete TOTP response package

#### Step 13: Send Response to Client
**Actor**: API Server
**Action**: Transmit TOTP code to frontend
**Response Format**:
- Status: 200 OK
- Headers: 
  - Content-Type: application/json
  - Cache-Control: no-store, no-cache
- Body: JSON with TOTP data
**Security**: Response headers prevent caching
**Output**: TOTP response delivered to client

#### Step 14: Client Processes Response
**Actor**: Frontend Application
**Action**: Handle TOTP generation response
**Process**:
1. Parse JSON response and extract TOTP data
2. Validate response format and required fields
3. Verify signature if signature verification enabled
4. Cache code locally with expiration time
5. Start countdown timer for user interface
**Output**: TOTP code ready for display

#### Step 15: Display Code to User
**Actor**: Frontend Application
**Action**: Present TOTP code in user interface
**Display Elements**:
- Large, readable 6-digit code
- Countdown timer showing remaining validity
- Service name and account identifier
- Copy-to-clipboard functionality
- Refresh button for manual regeneration
- Visual indicators for code freshness
**Accessibility**: High contrast, large fonts, screen reader support
**Output**: TOTP code visible to user

#### Step 16: User Copies/Uses Code
**Actor**: User
**Action**: Uses TOTP code for authentication
**Process**:
1. User reads 6-digit code from display
2. Optionally copies code to clipboard
3. Switches to external service (browser, app)
4. Enters code in 2FA prompt
5. Submits authentication form
**Timing**: User has remaining validity period to use code
**Output**: Code entered into external service

#### Step 17: Code Auto-Refresh Cycle
**Actor**: Frontend Application
**Action**: Automatically refresh expired codes
**Process**:
1. Monitor countdown timer continuously
2. When timer reaches 5 seconds remaining:
   - Start generating next code in background
   - Show visual warning of impending expiration
3. When timer reaches 0:
   - Request new code from server
   - Update display with fresh code
   - Reset countdown timer
4. Continue cycle automatically
**Output**: Seamless code refresh experience

### Security Features During Generation

#### Time Window Validation
**Purpose**: Prevent replay attacks and ensure code freshness
**Process**:
1. Server validates timestamp is within acceptable range
2. Rejects requests with timestamps too far in past/future
3. Accounts for reasonable clock skew (±30 seconds)
4. Logs suspicious timestamp patterns

#### Anti-Tampering Measures
**Purpose**: Detect and prevent code manipulation
**Process**:
1. All codes signed with quantum-safe Dilithium signatures
2. Client can verify code authenticity before display
3. Server validates request integrity
4. Tampered requests logged and blocked

#### Forward Secrecy Protection
**Purpose**: Ensure past codes remain secure even if current keys compromised
**Process**:
1. Time-based generation ensures old codes automatically invalid
2. Regular key rotation changes signing keys
3. Separate encryption keys for each user
4. Past codes cannot be regenerated without historical keys

### Error Handling Scenarios

#### Network Connectivity Issues
**Situation**: Device loses network connection during generation
**Recovery Process**:
1. Client detects network failure
2. Falls back to locally cached code if still valid
3. Shows "offline mode" indicator to user
4. Automatically retries when connection restored
5. Syncs time and regenerates when back online

#### Time Synchronization Problems
**Situation**: Device clock significantly out of sync
**Recovery Process**:
1. Server detects timestamp deviation in request
2. Returns time sync information in error response
3. Client adjusts local time offset
4. User notified of time sync issue
5. Regeneration attempted with corrected time

#### Secret Decryption Failure
**Situation**: Cannot decrypt TOTP secret for code generation
**Recovery Process**:
1. Server logs security incident immediately
2. User receives generic "generation failed" message
3. Account marked for key rotation
4. System health check triggered
5. User guided to re-setup account if necessary

#### Cryptographic Signature Failure
**Situation**: Cannot generate Dilithium signature for code
**Recovery Process**:
1. Server attempts to generate unsigned code
2. Warning logged about signature failure
3. Code marked as "unverified" in response
4. User notified of reduced security
5. Key rotation scheduled for next maintenance window

### Performance Optimizations

#### Code Caching Strategy
**Purpose**: Reduce server load and improve response time
**Implementation**:
- Cache valid codes for up to 25 seconds
- Include cache timestamp in response
- Client validates cache freshness
- Background refresh before expiration

#### Batch Generation for Multiple Accounts
**Purpose**: Efficiently generate codes for all user accounts
**Process**:
1. User requests "refresh all" operation
2. Server processes all accounts in single transaction
3. Parallel secret decryption for performance
4. Batch response with all current codes
5. Client updates all account displays simultaneously

#### Predictive Generation
**Purpose**: Prepare next code before current expires
**Implementation**:
- Generate next period's code 10 seconds early
- Cache both current and next codes
- Seamless transition at expiration boundary
- Reduced perceived latency for users

### Success Criteria
- Valid 6-digit TOTP code generated using quantum-safe algorithm
- Code properly signed with Dilithium signature
- Expiration time correctly calculated and communicated
- User can successfully authenticate with external service
- All generation events properly logged for audit
- Performance meets sub-second response requirements
- Code displays with accurate countdown timer

### Performance Expectations
- Secret decryption: < 50ms
- SHAKE-256 hash computation: < 10ms
- Dilithium signature generation: < 100ms
- Database operations: < 100ms
- Network transmission: < 200ms
- Total generation workflow: < 500ms
- Client display update: < 50ms

---

## TOTP Verification Workflow

### Overview
This workflow describes how the system verifies TOTP codes submitted by users or external services, ensuring quantum-safe authentication with comprehensive audit trails.

### Entities Involved
- **External Service**: System requesting TOTP verification (GitHub, Google, etc.)
- **Business Client**: Enterprise system using verification API
- **API Server**: Backend performing verification logic
- **Secret Manager**: Service handling TOTP secret decryption
- **Signature Verifier**: Service validating Dilithium signatures
- **Audit Logger**: Service recording verification events
- **Rate Limiter**: Service preventing brute force attacks

### Detailed Process Flow

#### Step 1: Verification Request Initiated
**Actor**: External Service or Business Client
**Action**: Submits TOTP code for verification
**Context**: User attempting to authenticate with 2FA
**Request Types**:
- Personal verification: User verifying own code
- Business verification: Enterprise verifying employee code
- Service integration: External service validating user
**Output**: Verification request received by system

#### Step 2: Authenticate Verification Request
**Actor**: API Server
**Action**: Validate request authorization
**Process for Personal Verification**:
1. Extract JWT token from Authorization header
2. Validate token signature and expiration
3. Extract user ID from token claims
4. Verify user account status (active, not locked)
**Process for Business Verification**:
1. Extract API key from X-API-Key header
2. Validate API key format and authenticity
3. Look up business account associated with key
4. Verify business account is active and in good standing
**Decision Point**: If authentication fails → Return HTTP 401
**Output**: Authenticated request context established

#### Step 3: Parse and Validate Request Data
**Actor**: API Server
**Action**: Extract and validate verification parameters
**Required Parameters**:
- account_id or user_id: Target account for verification
- code: 6-8 digit TOTP code to verify
- signature: Dilithium signature (optional but recommended)
- timestamp: Client timestamp (optional, for clock skew handling)
**Validation Rules**:
- Code: Must be numeric, 6-8 digits
- Account/User ID: Valid UUID format
- Signature: Valid base64 if provided
- Timestamp: Within reasonable range if provided
**Decision Point**: If validation fails → Return HTTP 400 with specific errors
**Output**: Validated verification parameters

#### Step 4: Apply Rate Limiting
**Actor**: Rate Limiter
**Action**: Check verification attempt frequency
**Rate Limiting Rules**:
- Maximum 20 verification attempts per minute per account
- Maximum 5 failed attempts per minute per IP address
- Exponential backoff after repeated failures
- Enhanced monitoring for business API usage
**Process**:
1. Identify rate limiting key (account + IP combination)
2. Check current attempt count within time window
3. Update attempt counter for this request
**Decision Point**: If rate limit exceeded → Return HTTP 429 with retry-after
**Output**: Rate limiting passed, verification allowed

#### Step 5: Retrieve Account Information
**Actor**: API Server
**Action**: Fetch target account configuration
**Process for Personal Verification**:
1. Query accounts table using account_id and authenticated user_id
2. Verify account ownership matches authenticated user
**Process for Business Verification**:
1. Query business_users table to map external_user_id to internal user_id
2. Query accounts table for user's accounts
3. Select appropriate account (first active account or specified service)
**Common Validations**:
- Account exists and is active
- Account belongs to correct user/business
- TOTP configuration is valid
**Decision Point**: If account not found → Return HTTP 404
**Output**: Account configuration retrieved with encrypted secret

#### Step 6: Decrypt TOTP Secret
**Actor**: Secret Manager
**Action**: Decrypt stored secret for verification
**Process**:
1. Retrieve appropriate decryption key:
   - User's personal encryption key for personal accounts
   - Business encryption key for business-managed accounts
2. Extract nonce from encrypted secret data
3. Decrypt secret using AES-256-GCM
4. Validate decrypted secret format and length
5. Load secret into secure memory for verification
**Security**: Secret decryption logged for audit
**Output**: Plaintext TOTP secret ready for code generation

#### Step 7: Determine Verification Time Windows
**Actor**: API Server
**Action**: Calculate valid time windows for verification
**Process**:
1. Get current server time in UTC
2. Apply client timestamp if provided and reasonable
3. Calculate current time slot: floor(timestamp / period)
4. Define verification window:
   - Current time slot (primary)
   - Previous time slot (for clock skew tolerance)
   - Next time slot (for minor future drift)
5. Account for maximum clock skew (configurable, default ±30 seconds)
**Output**: List of valid time slots for verification

#### Step 8: Generate Expected TOTP Codes
**Actor**: API Server
**Action**: Generate all valid codes for time windows
**Process for Each Time Window**:
1. Calculate time counter for the window
2. Initialize SHAKE-256 hash function
3. Input TOTP secret into hash function
4. Convert time counter to 8-byte big-endian format
5. Input time counter bytes into hash function
6. Extract 32 bytes of hash output
7. Apply dynamic truncation algorithm
8. Format to correct number of digits
**Output**: List of valid TOTP codes for verification period

#### Step 9: Verify Submitted Code
**Actor**: API Server
**Action**: Compare submitted code against valid codes
**Process**:
1. Compare submitted code against each generated valid code
2. Use constant-time comparison to prevent timing attacks
3. Track which time window matched (for audit logging)
4. Record verification attempt details
**Decision Point**: 
- If code matches → Proceed to signature verification
- If no match → Log failed attempt and return failure
**Output**: Code verification result (success/failure) with time window

#### Step 10: Verify Cryptographic Signature (If Provided)
**Actor**: Signature Verifier
**Action**: Validate Dilithium signature on TOTP code
**Process**:
1. Check if signature was provided in request
2. If signature provided:
   - Retrieve user's current public key from database
   - Construct signed message: user_id + ":" + code + ":" + timestamp
   - Verify Dilithium signature using public key
   - Validate signature covers correct data
3. If no signature provided:
   - Log signature absence for security monitoring
   - Continue with reduced security assurance
**Decision Point**: If signature invalid → Log security incident and fail verification
**Output**: Signature verification result

#### Step 11: Check for Replay Attacks
**Actor**: API Server
**Action**: Detect and prevent code reuse
**Process**:
1. Query recent verification history for this account
2. Check if same code was recently verified successfully
3. Compare timestamps to detect suspicious patterns
4. Implement sliding window to prevent replay:
   - Same code cannot be verified twice within same time period
   - Account for legitimate clock skew scenarios
**Decision Point**: If replay detected → Log security incident and fail verification
**Output**: Replay protection validation result

#### Step 12: Update Account Usage Statistics
**Actor**: API Server
**Action**: Record verification attempt and update metrics
**Process**:
1. Update last_used timestamp for account
2. Increment usage_count for successful verifications
3. Track verification patterns for fraud detection
4. Update business usage statistics if applicable
5. Record verification timing and method
**Output**: Account and business usage statistics updated

#### Step 13: Log Comprehensive Audit Event
**Actor**: Audit Logger
**Action**: Create detailed verification audit record
**Audit Information**:
- Event type: "totp_verified"
- User ID: account owner
- Account ID: verified account
- Business ID: if business verification
- Verification result: success/failure
- Code used: (hashed for security)
- Time window matched: which period was valid
- Signature verification: success/failure/not_provided
- IP address and user agent: request source
- Timestamp: verification time
- Algorithm used: SHAKE256
- Clock skew: if time adjustment applied
- Security incidents: replay attempts, suspicious patterns
**Output**: Verification event permanently recorded

#### Step 14: Handle Failed Verification
**Actor**: API Server (if verification failed)
**Action**: Process verification failure appropriately
**Process**:
1. Increment failed attempt counter for account
2. Apply progressive delays for repeated failures
3. Check if account should be temporarily locked
4. Log security incident details for investigation
5. Prepare failure response with appropriate error codes
**Security Measures**:
- No information leakage about why verification failed
- Consistent response timing to prevent enumeration
- Enhanced monitoring for brute force patterns
**Output**: Failure handled with security measures applied

#### Step 15: Prepare Verification Response
**Actor**: API Server
**Action**: Construct appropriate response based on result
**Success Response**:
- Status: 200 OK
- Body: JSON with verification confirmation
- Fields: valid=true, verified_at, account_id, user_id
- Security headers: no-cache, no-store
**Failure Response**:
- Status: 200 OK (to prevent information leakage)
- Body: JSON with verification failure
- Fields: valid=false, reason (generic), retry_allowed
- Rate limiting headers if applicable
**Output**: HTTP response ready for transmission

#### Step 16: Send Response to Requester
**Actor**: API Server
**Action**: Transmit verification result
**Response Security**:
- Consistent timing regardless of success/failure
- No detailed error information that could aid attacks
- Rate limiting headers for client guidance
- Audit trail correlation ID for debugging
**Output**: Verification response delivered to requester

#### Step 17: Post-Verification Security Actions
**Actor**: API Server
**Action**: Execute additional security measures
**For Successful Verification**:
1. Update user's last successful authentication time
2. Clear any failed attempt counters
3. Trigger any configured success webhooks
4. Update fraud detection models with successful pattern
**For Failed Verification**:
1. Increment security monitoring counters
2. Check for suspicious activity patterns
3. Trigger alerts if thresholds exceeded
4. Update blacklist if repeated abuse detected
**Output**: Security posture updated based on verification result

### Business Integration Specific Steps

#### Step 18: Business Webhook Notification (Business Verifications)
**Actor**: API Server
**Action**: Notify business systems of verification results
**Process**:
1. Check if business has configured webhooks
2. Prepare webhook payload with verification details
3. Sign webhook payload with business-specific key
4. Send HTTP POST to configured webhook URL
5. Handle webhook delivery failures with retry logic
**Webhook Payload**:
- Event: "totp_verified"
- User: external_user_id and internal mapping
- Result: success/failure with timestamp
- Service: which service/account was verified
- Metadata: verification context and security details
**Output**: Business systems notified of verification event

#### Step 19: Update Business Analytics
**Actor**: API Server
**Action**: Record verification in business analytics
**Metrics Updated**:
- Total verification count for billing
- Success rate trends for service quality monitoring
- User activity patterns for fraud detection
- Service usage statistics for optimization
- Security incident counts for risk assessment
**Output**: Business analytics databases updated

### Advanced Security Features

#### Adaptive Time Window Adjustment
**Purpose**: Automatically adjust for persistent clock skew
**Process**:
1. Track verification patterns for each user/device
2. Detect consistent time offset patterns
3. Gradually adjust acceptable time windows
4. Log adjustments for security review
5. Reset adjustments if suspicious changes detected

#### Machine Learning Fraud Detection
**Purpose**: Identify suspicious verification patterns
**Process**:
1. Analyze verification timing patterns
2. Detect geographic anomalies in requests
3. Identify impossible travel scenarios
4. Flag accounts with unusual verification frequency
5. Score verification requests for risk assessment

#### Quantum-Safe Verification Logging
**Purpose**: Ensure audit logs remain secure in quantum era
**Process**:
1. Hash all sensitive verification data with SHAKE-256
2. Sign audit log entries with Dilithium signatures
3. Create merkle tree of log entries for integrity
4. Periodically timestamp logs with quantum-safe protocols

### Error Recovery and Resilience

#### Database Connectivity Issues
**Situation**: Cannot access account or audit databases
**Recovery Process**:
1. Attempt verification using cached account data
2. Log all events to local storage for later sync
3. Implement graceful degradation with reduced functionality
4. Notify monitoring systems of database issues
5. Restore full functionality when connectivity returns

#### Time Synchronization Failures
**Situation**: Server time significantly out of sync
**Recovery Process**:
1. Detect time sync issues through NTP monitoring
2. Expand verification time windows temporarily
3. Log all verifications with time sync warnings
4. Attempt automatic time correction
5. Alert administrators if manual intervention required

#### Cryptographic System Failures
**Situation**: Cannot perform signature verification or secret decryption
**Recovery Process**:
1. Fall back to unsigned verification with security warnings
2. Log all cryptographic failures for investigation
3. Attempt verification with backup key material
4. Trigger emergency key rotation procedures
5. Notify security team of potential compromise

### Success Criteria
- Submitted TOTP code correctly verified using quantum-safe algorithms
- Cryptographic signatures properly validated when provided
- All verification attempts comprehensively logged
- Business systems notified of verification results
- Security measures prevent replay and brute force attacks
- Performance requirements met under normal and peak loads
- Error conditions handled gracefully without information leakage

### Performance Expectations
- Secret decryption: < 50ms
- TOTP code generation (all time windows): < 20ms
- Signature verification: < 100ms
- Database lookups: < 100ms
- Audit logging: < 50ms
- Total verification workflow: < 300ms
- Webhook notifications: < 2 seconds (non-blocking)

---

## Business Integration Workflow

### Overview
This workflow describes how enterprises integrate PQC Authenticator into their existing systems for employee authentication and access management.

### Entities Involved
- **Business Administrator**: Enterprise admin setting up integration
- **Enterprise System**: Company's existing authentication infrastructure
- **PQC Business API**: Backend services for enterprise clients
- **Employee**: End user requiring authentication
- **IT Admin Dashboard**: Management interface for business configuration
- **Webhook Service**: Real-time notification system
- **Analytics Engine**: Usage and security reporting system

### Detailed Process Flow

#### Step 1: Business Registration and Setup
**Actor**: Business Administrator
**Action**: Registers company for PQC Authenticator business services
**Process**:
1. Business admin visits PQC Authenticator business portal
2. Fills registration form with:
   - Company name and legal information
   - Contact email and phone number
   - Estimated number of employees
   - Desired service plan (basic, pro, enterprise)
   - Integration requirements and timeline
3. Submits registration request
**Required Information**:
- Company registration documents
- Technical contact information
- Security compliance requirements
- Integration scope and timeline
**Output**: Business registration request submitted

#### Step 2: Business Account Verification
**Actor**: PQC Business API
**Action**: Validates and approves business registration
**Process**:
1. Verify company information against business registries
2. Validate contact information and domain ownership
3. Assess security requirements and compliance needs
4. Determine appropriate service plan and pricing
5. Generate unique business ID and API credentials
**Verification Steps**:
- Domain ownership verification via DNS/email
- Business registration number validation
- Security questionnaire review
- Technical requirements assessment
**Output**: Business account approved and credentials generated

#### Step 3: API Key Generation and Distribution
**Actor**: PQC Business API
**Action**: Creates secure API credentials for business
**Process**:
1. Generate cryptographically secure API key:
   - Format: "pqc_business_" + 32 random bytes base64
   - Associated with specific business ID
   - Scoped permissions based on service plan
2. Create API key hash for secure storage
3. Generate secondary credentials for backup access
4. Prepare API documentation and integration guides
5. Send credentials via secure channel to business admin
**Security Measures**:
- API keys rotatable on demand
- Scoped permissions (read/write/admin)
- Rate limiting per API key
- Geographic access restrictions if requested
**Output**: Business receives API credentials and documentation

#### Step 4: Integration Planning and Configuration
**Actor**: Business Administrator
**Action**: Plans integration with existing systems
**Planning Considerations**:
1. Identify systems requiring 2FA integration:
   - VPN access systems
   - Internal applications
   - Cloud service accounts
   - Administrative interfaces
2. Map employee directories and user accounts:
   - Active Directory integration
   - LDAP server connections
   - Cloud identity providers (Azure AD, Okta)
3. Define authentication flows:
   - Single sign-on (SSO) integration
   - Multi-factor authentication (MFA) policies
   - Emergency access procedures
4. Plan user provisioning strategy:
   - Automatic provisioning from HR systems
   - Bulk import of existing employees
   - Just-in-time provisioning
**Output**: Integration plan and technical requirements defined

#### Step 5: Technical Integration Implementation
**Actor**: Enterprise System
**Action**: Implements API integration with PQC Authenticator
**Integration Types**:

**5a. Direct API Integration**:
```
Enterprise App → PQC Business API
1. Employee login with username/password
2. System prompts for 2FA code
3. Enterprise app calls: POST /api/business/v1/verify
4. PQC API validates code and returns result
5. Enterprise app grants/denies access based on result
```

**5b. SAML Integration**:
```
Enterprise → Identity Provider → PQC Authenticator
1. User accesses enterprise application
2. SAML authentication request to identity provider
3. Identity provider requests 2FA from PQC
4. PQC validates and returns SAML assertion
5. User granted access to enterprise application
```

**5c. OAuth/OpenID Connect Integration**:
```
Enterprise App → OAuth Provider → PQC Authenticator
1. User initiates OAuth flow
2. OAuth provider requests additional authentication
3. PQC Authenticator validates user identity
4. OAuth tokens issued with MFA claim
5. Enterprise app validates tokens and grants access
```

**Output**: Technical integration completed and tested

#### Step 6: Employee Provisioning Workflow
**Actor**: Business Administrator
**Action**: Provisions employees in PQC Authenticator system
**Provisioning Methods**:

**6a. Bulk Employee Import**:
1. Prepare CSV file with employee data:
   - Employee ID, name, email, department
   - Manager information and access levels
   - Required services and permissions
2. Upload file via business dashboard
3. System validates data format and completeness
4. Creates PQC accounts for all employees
5. Generates invitation emails with setup instructions

**6b. API-Based Provisioning**:
1. HR system calls PQC Business API for new employees
2. API endpoint: POST /api/business/v1/provision
3. Real-time account creation and activation
4. Automatic deprovisioning when employees leave
5. Synchronization with existing identity systems

**6c. Just-in-Time Provisioning**:
1. Employee attempts to access enterprise system
2. System checks if PQC account exists
3. If not exists, automatic account creation
4. Employee guided through setup process
5. Access granted after successful configuration

**Output**: All employees provisioned and ready for setup

#### Step 7: Employee Setup and Onboarding
**Actor**: Employee
**Action**: Sets up PQC Authenticator for work accounts
**Setup Process**:
1. Employee receives invitation email with setup instructions
2. Downloads PQC Authenticator app or accesses web interface
3. Creates personal account or links to existing account
4. Enters company-provided activation code
5. Associates work email with business account
6. Configures required work-related TOTP accounts
7. Tests authentication with enterprise systems
**Self-Service Options**:
- QR code setup for quick configuration
- Backup code generation for account recovery
- Multiple device registration for redundancy
- Help desk integration for support requests
**Output**: Employee ready to use 2FA for work systems

#### Step 8: Webhook Configuration for Real-Time Notifications
**Actor**: Business Administrator
**Action**: Configures webhooks for integration monitoring
**Webhook Setup**:
1. Configure webhook endpoint in enterprise system
2. Register webhook URL in PQC business dashboard
3. Select events for notification:
   - Employee authentication attempts
   - Account creation and deactivation
   - Security incidents and policy violations
   - Usage analytics and compliance reports
4. Configure webhook authentication and security
5. Test webhook delivery and error handling
**Webhook Events**:
- `user_authenticated`: Successful 2FA verification
- `user_failed_auth`: Failed authentication attempt
- `user_provisioned`: New employee account created
- `user_deprovisioned`: Employee account deactivated
- `security_incident`: Suspicious activity detected
- `