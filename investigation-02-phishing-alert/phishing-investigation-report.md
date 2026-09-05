# Investigation 02 — Phishing and Account Compromise Investigation

## Lab Disclaimer

This is a controlled cybersecurity learning investigation created for portfolio purposes. The data used in this investigation is simulated lab data and does not represent a real company incident.

## Executive Summary

A suspicious email was reported after an employee received an urgent message claiming that their Microsoft 365 account would be disabled.

The email contained an HTML attachment that opened a fake Microsoft 365 login page. The page requested the employee's credentials and submitted them to a suspicious external domain.

Shortly afterward, the employee's Microsoft 365 account was successfully accessed from an unusual source IP and an unknown device. The account was then accessed and an external mailbox forwarding rule was created.

The correlated evidence supports a verdict of **confirmed account compromise through credential phishing**.

## Initial Detection

The reported email contained the following information:

| Field | Value |
|---|---|
| Recipient | employee01@lab-company.example |
| Subject | Urgent: Your Microsoft 365 account will be disabled |
| Sender | security@microsoft-support.example |
| Reply-To | account-recovery@outlook-security.example |
| Attachment | Microsoft_Account_Verification.html |
| User Action | Employee opened the attachment |

The email claimed that the Microsoft 365 account would be permanently disabled within 24 hours unless the employee completed verification.

## Email Analysis

A mismatch was identified between the `From` and `Reply-To` addresses.

```text
From:
security@microsoft-support.example

Reply-To:
account-recovery@outlook-security.example
The domains appeared designed to resemble Microsoft-related services but were not the legitimate Microsoft domain.
This mismatch was treated as a phishing indicator rather than proof by itself.
Attachment Analysis
When the HTML attachment was opened, the sandbox recorded:
09:43:02  File opened:
Microsoft_Account_Verification.html

09:43:03  Browser opened:
https://login.microsoft-verification.example/

09:43:04  Page title:
Microsoft 365 Account Verification

09:43:06  User entered:
employee01@lab-company.example

09:43:08  Page requested:
Password
The page was designed to resemble a Microsoft 365 verification page.
Credential Submission
The network evidence showed:
09:43:08
POST /submit
Host: login.microsoft-verification.example

POST body:
username=employee01@lab-company.example
password=[REDACTED]
The submitted information was sent to the suspicious domain.
The site then returned:
09:43:13
HTTP 302 Redirect

Location:
https://www.microsoft.com/
The browser was subsequently redirected to the legitimate Microsoft website.
This behavior is consistent with a credential-phishing technique designed to collect credentials and then redirect the victim to a legitimate website.
Account Activity
Following the credential submission, Microsoft 365 authentication logs showed:
09:51:42
Account:
employee01@lab-company.example

Source IP:
198.51.100.27

Location:
Unusual for this account

09:51:45
Successful authentication

09:52:03
New session created

09:53:17
Mailbox access detected

09:54:02
Inbox forwarding rule created
The forwarding rule redirected incoming mail to:
external-mailbox@attacker.example
Sign-In Investigation
The successful sign-in contained several anomalies:
Indicator
Observation
Source IP
198.51.100.27
Location
Unusual for the account
Device
Unknown device
User Agent
Mozilla/5.0 (Windows NT 10.0; Win64; x64)
MFA
Not performed
Previous normal sign-in
Known company device
Previous location
Normal location
Previous MFA
Completed
The combination of an unusual source, unknown device, lack of MFA, and activity immediately following credential submission increased confidence that the account had been compromised.
Timeline
Time
Activity
09:42:17
Phishing email received
09:43:02
HTML attachment opened
09:43:03
Fake Microsoft 365 login page opened
09:43:06
Username entered
09:43:08
Password requested and credentials submitted
09:43:13
Suspicious site returned HTTP 302 redirect
09:43:14
Browser redirected to legitimate Microsoft website
09:51:42
Unusual Microsoft 365 sign-in detected
09:51:45
Successful authentication
09:52:03
New session created
09:53:17
Mailbox access detected
09:54:02
External forwarding rule created
Attack Chain
The evidence supports the following attack chain:
Phishing email
        ↓
HTML attachment opened
        ↓
Fake Microsoft 365 login page
        ↓
Credentials entered
        ↓
Credentials submitted to suspicious domain
        ↓
Unusual successful Microsoft 365 authentication
        ↓
Unknown device / unusual source
        ↓
Mailbox accessed
        ↓
External forwarding rule created
        ↓
Confirmed account compromise
Indicators of Compromise
Indicator
Type
login.microsoft-verification.example
Phishing domain
198.51.100.27
Source IP
security@microsoft-support.example
Sender
account-recovery@outlook-security.example
Reply-To address
Microsoft_Account_Verification.html
Attachment
external-mailbox@attacker.example
External forwarding destination
Final Verdict
Confirmed account compromise through credential phishing.
The evidence shows that the employee received and opened a phishing attachment, entered credentials into a fake Microsoft 365 login page, and had those credentials submitted to a suspicious external domain.
Shortly afterward, the account was successfully accessed from an unusual source using an unknown device. The mailbox was accessed and an external forwarding rule was created.
The combination of credential harvesting, anomalous authentication, mailbox access, and unauthorized forwarding activity provides sufficient evidence to classify the account as compromised.
The evidence does not establish the identity of the human attacker.
Containment and Response Recommendations
Immediate response actions would include:
Disable or temporarily restrict the compromised account according to incident-response procedures.
Reset the user's password.
Revoke active sessions and authentication tokens.
Require MFA and verify MFA configuration.
Remove the unauthorized external forwarding rule.
Block the phishing domain where appropriate.
Search the environment for the same phishing domain and indicators.
Review mailbox activity for unauthorized access or data exposure.
Check whether other users received the same phishing email.
Investigate whether the compromised account was used to send additional phishing emails.
Lessons Learned
This investigation demonstrated several important SOC investigation techniques:
Identifying phishing indicators in email headers.
Comparing From and Reply-To addresses.
Investigating HTML attachments.
Analyzing suspicious URLs and domains.
Understanding HTTP POST requests.
Correlating credential submission with authentication events.
Investigating unusual source IP addresses and devices.
Reviewing Microsoft 365 sign-in activity.
Investigating mailbox access.
Identifying suspicious forwarding rules.
Building an attack timeline.
Correlating multiple indicators before reaching a final verdict.
Conclusion
This controlled investigation demonstrates how a SOC analyst can move from an initial phishing alert to a confirmed account compromise by correlating email, attachment, web, authentication, and mailbox evidence.
The investigation did not rely on a single indicator. Instead, multiple related events formed a consistent attack chain from credential phishing to unauthorized account access and post-compromise mailbox activity.
