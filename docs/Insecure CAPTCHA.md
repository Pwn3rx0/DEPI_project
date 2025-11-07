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

