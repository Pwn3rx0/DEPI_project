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