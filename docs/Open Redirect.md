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