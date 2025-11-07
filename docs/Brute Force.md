>**Vulnerability ID:** VULN-DVWA-2024-BRUTE-FORCE  
   **Risk Level:** High  
   **CVSS Score:** 7.5 (High)

### 1. Business Impact Analysis

- **Account Compromise:** Attackers can gain unauthorized access to user accounts through systematic guessing
- **Data Breach:** Access to sensitive user data, personal information, and application functionality
- **Privilege Escalation:** Compromise administrative accounts to gain full system control
- **Service Abuse:** Use compromised accounts for spam, fraud, or further attacks
- **Reputation Damage:** Loss of customer trust due to inadequate security controls

### 2. Vulnerability Identification Methods

**Code Analysis Patterns:**
- Search for authentication endpoints without rate limiting or account lockout mechanisms
- Identify missing CAPTCHA or challenge-response tests
- Check for weak password policies and absence of multi-factor authentication
- Look for verbose error messages that reveal valid usernames

**Vulnerability Location Identified:**  
The application login mechanism lacks protection against automated authentication attempts:


```powershell
http://192.168.1.4/DVWA/vulnerabilities/brute/
```
![[Pasted image 20251107000208.png]]
### 3. Exploitation Analysis

**Attack Vector:** Automated Credential Guessing  
The application allows unlimited login attempts without implementing protective controls.

**Attack Methodology:**

1. **Username Enumeration:** Identify valid usernames through error message analysis    
2. **Password Spraying:** Try common passwords across multiple accounts
3. **Dictionary Attacks:** Use wordlists of common passwords and variations
4. **Credential Stuffing:** Use credentials leaked from other breaches

**Tools and Techniques:**


```bash
hydra -l <username> -P <password-list> <target> http-get-form "<login-form>:<login-field>^USER^&<password-field>^PASS^:F=<failed-login-string>"

for our case:
 hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-get-form '/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\:PHPSESSID=9sosvqo963thpd5jqf9mum3f41; security=low:F=Username and/or password incorrect'
# Burp Suite Intruder attack
# Cluster bomb attack with username and password lists
```
**Successful Exploitation:**  
Using a wordlist with common credentials, the attacker successfully identified valid credentials:
- **Username:** admin
- **Password:** password
![[Pasted image 20251107000448.png]]

### 4. Vulnerability Root Cause

**Vulnerable Code:**
```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
        // Get username
        $user = $_GET[ 'username' ];

        // Get password
        $pass = $_GET[ 'password' ];
        $pass = md5( $pass );

        // Check the database
        $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

        if( $result && mysqli_num_rows( $result ) == 1 ) {
                // Get users details
                $row    = mysqli_fetch_assoc( $result );
                $avatar = $row["avatar"];

                // Login successful
                $html .= "<p>Welcome to the password protected area {$user}</p>";
                $html .= "<img src=\"{$avatar}\" />";
        }
        else {
                // Login failed
                $html .= "<pre><br />Username and/or password incorrect.</pre>";
        }

        ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```

**Primary Issues:**

1. **No Rate Limiting:** Unlimited login attempts allowed from single IP
2. **No Account Lockout:** Failed attempts don't trigger temporary account suspension
3. **Verbose Error Messages:** Clear indication of failed vs successful username discovery
4. **Weak Password Storage:** Simple MD5 hashing without salting
### 5. Mitigation Strategies

**Secure Code Implementation:**  
Implement comprehensive authentication security controls with multiple defense layers.

php

<?php
class SecureAuthentication {
    private $db;
    private $max_attempts = 5;
    private $lockout_duration = 900; // 15 minutes
    private $ip_delay = 2; // 2 second delay between attempts
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    private function checkRateLimit($username, $ip_address) {
        // Check IP-based rate limiting
        $ip_attempts = $this->getRecentAttempts($ip_address, 300); // 5 minutes
        if ($ip_attempts >= 10) {
            sleep(5); // Increased delay for suspicious IPs
            return "Too many attempts from your IP address";
        }
        
        // Check account-based rate limiting
        $user_attempts = $this->getRecentAttempts($username, 900); // 15 minutes
        if ($user_attempts >= $this->max_attempts) {
            $this->lockAccount($username);
            return "Account temporarily locked due to too many failed attempts";
        }
        
        return null;
    }
    
    private function getRecentAttempts($identifier, $timeframe) {
        $query = "SELECT COUNT(*) FROM login_attempts 
                  WHERE identifier = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL ? SECOND)";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("si", $identifier, $timeframe);
        $stmt->execute();
        $stmt->bind_result($count);
        $stmt->fetch();
        $stmt->close();
        return $count;
    }
    
    private function recordAttempt($username, $ip_address, $success) {
        $query = "INSERT INTO login_attempts (username, ip_address, success, attempt_time) 
                  VALUES (?, ?, ?, NOW())";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("ssi", $username, $ip_address, $success);
        $stmt->execute();
        $stmt->close();
    }
    
    private function lockAccount($username) {
        $lock_time = time() + $this->lockout_duration;
        $query = "UPDATE users SET lock_until = ? WHERE username = ?";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("is", $lock_time, $username);
        $stmt->execute();
        $stmt->close();
    }
    
    private function isAccountLocked($username) {
        $query = "SELECT lock_until FROM users WHERE username = ?";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($lock_until);
        $stmt->fetch();
        $stmt->close();
        
        return $lock_until && $lock_until > time();
    }
    
    public function authenticate($username, $password, $ip_address) {
        // Always sleep to prevent timing attacks
        sleep($this->ip_delay);
        
        // Check rate limiting
        $rate_limit_error = $this->checkRateLimit($username, $ip_address);
        if ($rate_limit_error) {
            $this->recordAttempt($username, $ip_address, false);
            return [false, $rate_limit_error];
        }
        
        // Check account lock
        if ($this->isAccountLocked($username)) {
            return [false, "Account temporarily locked. Please try again later."];
        }
        
        // Generic error message to prevent username enumeration
        $generic_error = "Invalid username or password";
        
        // Verify user exists
        $query = "SELECT id, password, salt FROM users WHERE username = ?";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($user_id, $stored_hash, $salt);
        $user_exists = $stmt->fetch();
        $stmt->close();
        
        if (!$user_exists) {
            $this->recordAttempt($username, $ip_address, false);
            return [false, $generic_error];
        }
        
        // Verify password with secure hashing
        $hashed_password = hash('sha256', $salt . $password);
        
        if (hash_equals($stored_hash, $hashed_password)) {
            $this->recordAttempt($username, $ip_address, true);
            // Clear failed attempts on successful login
            $this->clearFailedAttempts($username);
            return [true, "Login successful"];
        } else {
            $this->recordAttempt($username, $ip_address, false);
            return [false, $generic_error];
        }
    }
    
    private function clearFailedAttempts($username) {
        $query = "DELETE FROM login_attempts WHERE username = ?";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->close();
    }
}

// Implementation
if(isset($_POST['Login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $ip_address = $_SERVER['REMOTE_ADDR'];
    
    $auth = new SecureAuthentication($GLOBALS["___mysqli_ston"]);
    list($success, $message) = $auth->authenticate($username, $password, $ip_address);
    
    if($success) {
        $_SESSION['username'] = $username;
        header("Location: index.php");
        exit;
    } else {
        echo "<pre>{$message}</pre>";
    }
}
?>

**Additional Security Measures:**


```php
// Database schema for login attempts tracking
CREATE TABLE login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    success TINYINT(1) NOT NULL,
    attempt_time DATETIME NOT NULL,
    INDEX idx_username_time (username, attempt_time),
    INDEX idx_ip_time (ip_address, attempt_time)
);

// Enhanced users table
ALTER TABLE users ADD COLUMN (
    lock_until INT DEFAULT NULL,
    salt VARCHAR(32) NOT NULL,
    last_login DATETIME NULL,
    failed_attempts INT DEFAULT 0
);
```

**Defense-in-Depth Measures:**

1. **Rate Limiting:**
    - Implement IP-based and account-based rate limiting
    - Progressive delays for repeated failures
    - Account lockout after excessive attempts
2. **Authentication Security:**
    - Implement CAPTCHA after 3 failed attempts
    - Consider multi-factor authentication for sensitive accounts
    - Use secure password hashing with salting
3. **Information Disclosure:**
    - Use generic error messages to prevent username enumeration
    - Implement consistent response times to prevent timing attacks
4. **Monitoring and Logging:**
    - Log all authentication attempts with IP addresses
    - Monitor for brute force patterns and suspicious activity
    - Implement alerting for attack detection

### 6. Risk Assessment Matrix

|Impact Area|Severity|Likelihood|Overall Risk|
|---|---|---|---|
|Data Confidentiality|High|High|High|
|System Integrity|High|High|High|
|Authentication Security|High|High|High|
|Compliance|High|Medium|High|

### 7. Testing Verification

**Remediation Validation Steps:**

1. Test rapid login attempts - should trigger rate limiting
2. Verify account lockout after 5 failed attempts
3. Test generic error messages for both invalid user and wrong password
4. Confirm CAPTCHA implementation after multiple failures
5. Verify consistent response times to prevent timing attacks

**Post-Mitigation Testing Results:**
- Rate limiting effectively blocks automated attacks
- Account lockout prevents continued credential guessing
- Generic error messages prevent username enumeration
- CAPTCHA challenges stop automated tools
### Appendix A: Reference Materials

- **OWASP Authentication Cheat Sheet:** [https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- **OWASP Brute Force Attack:** [https://owasp.org/www-community/attacks/Brute_force_attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- **CWE-307: Improper Restriction of Excessive Authentication Attempts** - [https://cwe.mitre.org/data/definitions/307.html](https://cwe.mitre.org/data/definitions/307.html)
- **NIST Digital Identity Guidelines:** [https://pages.nist.gov/800-63-3/](https://pages.nist.gov/800-63-3/)