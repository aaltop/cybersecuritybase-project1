# Cyber security project 1

See https://cybersecuritybase.mooc.fi/module-3.1.

The project is meant to contain at least five different flaws
from the [OWASP top ten list](https://owasp.org/Top10/) of cyber
security flaws, with a fix included for each. The project will use the 2021 list for these
flaws. The flaws are as follows:

1. [Broken access control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
    - "Access control enforces policy such that users cannot act outside of their intended permissions."
    For example, one user is able to access another's sensitive information
    by directly navigating to a URL which is otherwise simply not
    shown to the unauthorised user. As a fix, The operation used
    to fetch the information should require authentication and authorisation
    checks.
2. [Cryptographic failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
    - In general, any sensitive data should be properly secured using
    strong cryptographic algorithms. One issue could be using a pseudo-random
    number generation algorithm that is not cryptographically secure
    for tasks that require said security.
3. [Injection](https://owasp.org/Top10/A03_2021-Injection/)
    - In general, data/input from untrusted sources is not properly
    validated/escaped, allowing the untrusted sources to, for example,
    execute code on the backend that they should not be able to
    by "injecting" instructions. A classic example is SQL injection,
    where input can be specially crafted to escape the intended backend
    SQL query, and perform a new query of the user's choosing. This may potentially
    allow unfettered access to the service's database, and therefore
    access to sensitive data.
4. [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
    - Conceptually more abstract, deals with simply including security considerations
    more in the process of designing a piece of software and
    its overall lifecycle.
5. [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
    - Proper configuration of the environment is lacking. One
    example might be to use development settings in production, such
    as a debug option, which may give away important information about
    the workings of the software.
6. [Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
    - Fairly self-explanatory. For example, using a version of a library
    for which a vulnerability has been found when there is a patched
    version available. Naturally, this would leave the software
    vulnerable to the vulnerability.
7. [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
    - Concerns the improper use of session IDs/tokens and insufficient
    authentication measures. For example, allowing a very short and simple
    password. This makes it easier for malicious actors to gain access
    to sensitive details. 
8. [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
    - Concerns lacking checks for whether software and data is trustworthy.
    For example, not signing and checking signatures of downloaded software (and in
    some cases data), or getting software from untrusted sources. This
    might lead to infected libraries being included, potentially allowing malicious
    actors access to the software and perhaps more.
9. [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
    - Concerns insufficient logging of events and alerting about suspicious
    activity. For example, any sign-ins, failed or not, should be logged
    so that activity can be tracked. Especially failed sign-ins could
    be a sign of an attempt to gain illicit access to someone's account,
    perhaps by way of a brute-force attack. In this case, logs might include details
    such as IP addresses, allowing some form of identification of the malicious
    actor. In turn, logs would reveal the username of the account, allowing
    possibly for the actual user to be notified through their email,
    possibly suggesting a change of password.
10. [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
    - Effectively a sub-category of "Injection", SSRF can happen
    when a user is allowed to input a URL, and that URL is not
    checked for validity but is used to fetch content. This allows
    an attacker to make a request to any address from inside the server,
    such as potentially the file system of the environment the system
    is running on, allowing access to files on the system.