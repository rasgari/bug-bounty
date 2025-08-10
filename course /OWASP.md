OWASP:

===>>> path traversal:
                      --->>> ../../index.php
                      --->>> ../../.htaccess
                      --->>> ../../etc/passwd



===>>> mis configuration:
            ===>>> directory listing


===>>> word list:
       ===>>> admin , upload , application , config , database , ownerapi , restapi , routes , api-model , sql , htaccess ,  


======================================================

===>>> OWASP Top 10–2021 Tryhackme Writeup
https://infosecwriteups.com/owasp-top-10-2021-tryhackme-writeup-56f2a04c895e?source=rss------bug_bounty-5



======================================================
===>>> API
      ===>>>apisecurity.io


======================================================

===>>> OWASP Cheatsheet: Docker Pentesting Cheat Sheet
Cheatsheet: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

======================================================


👉 OWASP TOP 10 VULNERABILITIES WITH EXAMPLES 👈 
1. Broken Access Control
Description: Users can access resources or perform actions they should not have permission to access.
Example: 
🔴 A standard user can access an admin panel by directly navigating to /admin without proper validation.
🔴 A user can manipulate an API request to access another user’s data: 
GET /api/user/12345 
🔴 Changing 12345 to another user ID like 12346 exposes sensitive information.

2. Cryptographic Failures (Sensitive Data Exposure)
Description: Sensitive data is not adequately protected, making it accessible to attackers.
Example: 
🔴Storing passwords in plaintext instead of hashing them.
🔴Using HTTP (unencrypted) instead of HTTPS to transmit login credentials.

3. Injection
Description: Untrusted data is sent to an interpreter (like SQL, NoSQL, or LDAP) without proper sanitization.
Example: 
🔴SQL Injection: 
🔴SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'; The injected query allows unauthorized access.

4. Insecure Design
Description: The application lacks secure design principles, making it inherently vulnerable.
Example: 
🔴Allowing unlimited failed login attempts without account lockout, enabling brute force attacks.

5. Security Misconfiguration
Description: Incorrect or incomplete configurations leave the system exposed.
Example: 
🔴Leaving the default username/password for a database, such as root:password.
🔴Exposing debug information in production environments (/debug endpoint active).

6. Vulnerable and Outdated Components
Description: Using outdated software or dependencies with known vulnerabilities.
Example: 
🔴Using an old version of a JavaScript library like jQuery 1.8, which has known security flaws.

7. Identification and Authentication Failures
Description: Flaws in authentication mechanisms allow attackers to impersonate users.
Example: 
🔴A weak password reset token that attackers can guess or brute-force.
Session fixation where an attacker forces a user to use a specific session ID.

8. Software and Data Integrity Failures
Description: Applications do not validate the integrity of software or data.
Example: 
🔴Using unsigned or improperly verified updates that an attacker could tamper with during delivery.

9. Security Logging and Monitoring Failures
Description: Lack of sufficient logging and monitoring to detect security events.
Example: 
🔴No logs are generated for failed login attempts or suspicious behavior, leaving brute force attacks undetected.

10. Server-Side Request Forgery (SSRF)
Description: The server is tricked into making unauthorized requests to internal or external resources.
Example: 
🔴An attacker submits a malicious URL to a feature that fetches data from a remote server

======================================================
