<div align="center">

# SQL Injection in Modified eCommerce Shopsoftware 3.3.0 via `admin/csv_backend.php`

<a href="https://github.com/carlosalbertotuma/RedScan_Research_Team"><img src="https://img.shields.io/badge/RedScan-Research%20Team-B22222?style=for-the-badge" alt="RedScan Research Team"></a>
<img src="https://img.shields.io/badge/CWE--89-SQL%20Injection-orange?style=for-the-badge" alt="CWE-89 SQL Injection">
<img src="https://img.shields.io/badge/Severity-High%20(preliminary)-red?style=for-the-badge" alt="Severity High (preliminary)">

</div>

Time-Based Blind SQL Injection (CWE-89), identified by static analysis and confirmed by dynamic validation, in the administrative CSV configuration functionality of [Modified eCommerce Shopsoftware](https://github.com/modified-shop/modified-shop) 3.3.0 rev 16825, via the `CSV_CAT_DEPTH` parameter on `action=save`.

| | |
|---|---|
| **Vulnerability** | Time-Based Blind SQL Injection |
| **Product** | Modified eCommerce Shopsoftware  ([modified-shop/modified-shop](https://github.com/modified-shop/modified-shop)) |
| **Affected Version** | 3.3.0 rev 16825 |
| **Affected Component** | `admin/csv_backend.php` |
| **Affected Action** | `save` |
| **Vulnerable Parameter** | `CSV_CAT_DEPTH` |
| **Vulnerability Type** | SQL Injection |
| **CWE** | CWE-89 |
| **CAPEC** | CAPEC-66 |
| **Suggested Severity** | High (preliminary assessment) |
| **CVE** | Not assigned |
| **CVSS** | Not assessed |
| **Status** | Vendor notification sent; awaiting response |
| **Publication Date** | November 12, 2026 |
| **Last Updated** | November 12, 2026 |

---

## Table of Contents

- [1. Vulnerability Identification](#1-vulnerability-identification)
- [2. Vulnerability Description](#2-vulnerability-description)
- [3. Technical Evidence](#3-technical-evidence)
  - [3.1. Vulnerable source code](#31-vulnerable-source-code)
  - [3.2. Affected parameter](#32-affected-parameter)
  - [3.3. Database environment](#33-database-environment)
  - [3.4. Database query observation](#34-database-query-observation)
- [4. Preconditions and Impact](#4-preconditions-and-impact)
  - [4.1. Preconditions](#41-preconditions)
  - [4.2. Demonstrated impact](#42-demonstrated-impact)
  - [4.3. Potential impact](#43-potential-impact)
- [5. Recommendation](#5-recommendation)
- [6. Conclusion](#6-conclusion)
- [7. Dynamic Validation — Proof of Concept](#7-dynamic-validation--proof-of-concept)
  - [7.1. Validation environment](#71-validation-environment)
  - [7.2. Proof of Concept payload](#72-proof-of-concept-payload)
  - [7.3. HTTP response observation](#73-http-response-observation)
  - [7.4. Timing comparison](#74-timing-comparison)
  - [7.5. MariaDB General Query Log confirmation](#75-mariadb-general-query-log-confirmation)
  - [7.6. Validation result](#76-validation-result)
- [8. Vulnerability Classification](#8-vulnerability-classification)
- [9. Mitigation](#9-mitigation)
  - [9.1. Use prepared statements](#91-use-prepared-statements)
  - [9.2. Validate configuration values](#92-validate-configuration-values)
  - [9.3. Restrict configuration keys](#93-restrict-configuration-keys)
  - [9.4. Review related SQL queries](#94-review-related-sql-queries)
  - [9.5. Restrict administrative access](#95-restrict-administrative-access)
- [10. Detection and Monitoring](#10-detection-and-monitoring)
  - [10.1. HTTP and application log monitoring](#101-http-and-application-log-monitoring)
  - [10.2. Indicators of Compromise (IoCs)](#102-indicators-of-compromise-iocs)
  - [10.3. MariaDB Database Monitoring](#103-mariadb-database-monitoring)
  - [10.4. Behavioral Correlation](#104-behavioral-correlation)
  - [10.5. Recommended Monitoring](#105-recommended-monitoring)
- [11. Coordinated Vulnerability Disclosure Timeline](#11-coordinated-vulnerability-disclosure-timeline)
- [12. Vendor Communication](#12-vendor-communication)
- [13. Credits and Acknowledgments](#13-credits-and-acknowledgments)
- [14. References](#14-references)
- [15. Revision History](#15-revision-history)
- [16. Legal Notice](#16-legal-notice)

---

## 1. Vulnerability Identification

A Time-Based Blind SQL Injection vulnerability was identified in Modified eCommerce Shopsoftware version 3.3.0 rev 16825.

The vulnerability affects the administrative CSV configuration functionality implemented in:

```text
admin/csv_backend.php
```

The issue occurs during the processing of the `save` action, where the application incorporates the value of the `CSV_CAT_DEPTH` configuration parameter directly into an SQL statement without adequate parameterization.

An authenticated administrator capable of accessing the affected CSV configuration functionality can submit crafted input that modifies the structure of the SQL query.

During laboratory validation, the vulnerability was confirmed through a time-based SQL injection payload using the MariaDB `SLEEP()` function.

- **Researcher:** Anderson Dos Reis Gonzaga, *RedScan Research Team*

---

## 2. Vulnerability Description

The affected component constructs an SQL `UPDATE` statement by concatenating a value obtained from the HTTP request directly into the query.

The vulnerable implementation was identified at approximately line 50:

```php
xtc_db_query("UPDATE ".TABLE_CONFIGURATION." SET configuration_value='".
$_POST[$configuration['configuration_key']]."' where configuration_key='".$configuration['configuration_key']."'");
```

The application inserts the submitted configuration value into the SQL statement without using parameterized queries or an equivalent safe database abstraction mechanism.

As a result, specially crafted input can escape the intended value context and introduce additional SQL expressions into the statement.

The vulnerability was confirmed using a time-based payload that caused MariaDB to execute the `SLEEP()` function, introducing a measurable delay in the application's response. This behavior demonstrates that user-controlled input can influence the execution of the database query.

---

## 3. Technical Evidence

### 3.1. Vulnerable source code

The vulnerable code is located in:

```text
admin/csv_backend.php
```

The relevant implementation is:

```php
xtc_db_query("UPDATE ".TABLE_CONFIGURATION." SET configuration_value='".
$_POST[$configuration['configuration_key']]."' where configuration_key='".$configuration['configuration_key']."'");
```

The value submitted through the configuration parameter is concatenated directly into the SQL statement.

### 3.2. Affected parameter

```text
CSV_CAT_DEPTH
```

The parameter is processed as part of the CSV administration configuration update functionality.

### 3.3. Database environment

The vulnerability was validated in a controlled laboratory environment using MariaDB.

### 3.4. Database query observation

The MariaDB General Query Log recorded the following statement during the time-based validation:

```sql
UPDATE configuration
SET configuration_value='x'
WHERE configuration_key='CSV_CAT_DEPTH'
AND IF(1=1,SLEEP(5),0) #'
WHERE configuration_key='CSV_CAT_DEPTH'
```

The recorded statement demonstrates that the submitted value altered the SQL query structure and introduced an additional conditional expression containing `SLEEP(5)`.

The `#` character was interpreted as a SQL comment marker by MariaDB, allowing the remainder of the original statement to be commented out. This database-side observation provides direct evidence that the injected expression reached the SQL execution layer.

---

## 4. Preconditions and Impact

### 4.1. Preconditions

Successful exploitation requires:

- An authenticated administrative session.
- Access to the CSV configuration functionality.
- Permission to submit configuration updates through the affected component.
- A valid CSRF token or the ability to submit a request accepted by the application.
- Access to the affected application endpoint.

The vulnerability was demonstrated in an authenticated administrative context.

### 4.2. Demonstrated impact

The following behavior was demonstrated during laboratory validation:

- User-controlled input altered the structure of the SQL statement.
- An additional SQL conditional expression was executed.
- The MariaDB `SLEEP()` function introduced a measurable delay.
- The database General Query Log recorded the injected SQL expression.

### 4.3. Potential impact

Depending on the database permissions, application architecture, and the scope of accessible SQL operations, SQL injection vulnerabilities may potentially allow:

- Unauthorized access to database information.
- Unauthorized modification of database records.
- Disclosure of sensitive application data.
- Further compromise of application functionality.

These are potential consequences of the vulnerability class and were not independently demonstrated during this assessment. No sensitive data extraction, unauthorized access to other database tables, operating system command execution, or service outage was demonstrated during the validation.

---

## 5. Recommendation

The vendor should correct the vulnerable SQL query construction in `admin/csv_backend.php`. The application must not concatenate user-controlled values directly into SQL statements.

The recommended remediation is to:

1. Replace dynamically concatenated SQL statements with parameterized queries or prepared statements.
2. Validate the expected data type and format of the `CSV_CAT_DEPTH` value.
3. Apply strict allowlisting to configuration keys that can be updated through the CSV administration module.
4. Review other database queries that incorporate values originating from HTTP request parameters.
5. Ensure that the application's database abstraction layer safely handles user-controlled values.

Any remediation should preserve the intended CSV configuration functionality while preventing user input from modifying SQL query structure.

---

## 6. Conclusion

The assessment identified and confirmed a Time-Based Blind SQL Injection vulnerability in Modified eCommerce Shopsoftware version 3.3.0 rev 16825.

The vulnerability affects the `CSV_CAT_DEPTH` parameter processed by the `save` action in `admin/csv_backend.php`.

The issue was confirmed through controlled time-based testing and corroborated by the MariaDB General Query Log, which recorded the injected SQL expression.

The observed behavior demonstrates that the application does not adequately separate user-controlled data from SQL query syntax in the affected code path. The vendor should prioritize remediation and review similar query construction patterns throughout the application.

---

## 7. Dynamic Validation — Proof of Concept

> **Warning:** For use in authorized environments only. Testing on production systems without authorization is illegal.

### 7.1. Validation environment

The vulnerability was validated in a controlled laboratory environment. The test involved an authenticated administrative session and the CSV configuration update functionality.

- **Affected endpoint:** `http://[TARGET]/admin/csv_backend.php?gID=20&action=save`
- **Vulnerable parameter:** `CSV_CAT_DEPTH`
- **Validation date:** November 12, 2026

### 7.2. Proof of Concept payload

The following payload was submitted through the affected configuration parameter:

```text
CSV_CAT_DEPTH=x' WHERE configuration_key='CSV_CAT_DEPTH' AND IF(1=1,SLEEP(5),0) #
```

The payload attempts to introduce an additional SQL condition and execute a five-second delay through MariaDB's `SLEEP()` function.

### 7.3. HTTP response observation

The browser request returned the following observed behavior:

| Observation | Result |
|---|---|
| **HTTP Status** | `200 OK` |
| **Redirected** | Yes |
| **Final URL** | `[TARGET]/admin/csv_backend.php` |
| **Response Time** | 5.066 seconds |
| **Response Length** | 31,580 bytes |

The browser response time was consistent with the delay introduced by the SQL payload.

### 7.4. Timing comparison

The following measurements were collected during testing:

| Test | Measured Time |
|---|---|
| Control request | `0.012364 seconds` |
| Request containing `SLEEP(5)` | `5.014301 seconds` |
| Approximate time difference | `5.002 seconds` |
| Additional browser validation | `5.066 seconds` |

The difference between the control request and the injected request demonstrates a delay consistent with the execution of the `SLEEP(5)` expression.

### 7.5. MariaDB General Query Log confirmation

The MariaDB General Query Log recorded the following SQL statement:

```sql
UPDATE configuration
SET configuration_value='x'
WHERE configuration_key='CSV_CAT_DEPTH'
AND IF(1=1,SLEEP(5),0) #'
WHERE configuration_key='CSV_CAT_DEPTH'
```

This observation confirms that the injected expression reached the database query execution layer. The test also modified the `CSV_CAT_DEPTH` configuration value to `x`.

The validation was limited to confirming SQL query manipulation and time-based behavior. No attempt was made to extract sensitive information or access unrelated database tables.

### 7.6. Validation result

<img src="https://img.shields.io/badge/Validation-Confirmed%20in%20laboratory-brightgreen?style=for-the-badge" alt="Confirmed in laboratory">

The vulnerability was successfully reproduced. The timing measurements and MariaDB General Query Log provide independent evidence of the SQL injection behavior.

---

## 8. Vulnerability Classification

| Classification | Value |
|---|---|
| **Vulnerability Type** | SQL Injection |
| **Variant** | Time-Based Blind SQL Injection |
| **CWE** | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| **CAPEC** | CAPEC-66 — SQL Injection |
| **Affected Component** | `admin/csv_backend.php` |
| **Affected Parameter** | `CSV_CAT_DEPTH` |
| **Suggested Severity** | High (preliminary) |
| **CVSS 3.1** | Not assessed |
| **CVE** | Not assigned |

The suggested **High** severity is preliminary and should not be interpreted as an official CVSS rating. A formal CVSS assessment would require a complete evaluation of the exploitation conditions, privileges, scope, and demonstrated impact.

---

## 9. Mitigation

The following remediation measures are recommended.

### 9.1. Use prepared statements

Replace dynamically constructed SQL statements with prepared statements or parameterized queries.

The following example illustrates the recommended approach:

```php
$stmt = $pdo->prepare(
    "UPDATE configuration
     SET configuration_value = :value
     WHERE configuration_key = :key"
);

$stmt->execute([
    ':value' => $configurationValue,
    ':key' => $configurationKey
]);
```

> *Note:* This is an illustrative example and must be adapted to the application's actual database abstraction layer. It has not been validated as a drop-in patch for Modified Shop.

### 9.2. Validate configuration values

Validate the `CSV_CAT_DEPTH` parameter according to its expected data type and business rules. Reject unexpected characters, formats, or values that do not comply with the application's configuration requirements. Input validation should complement prepared statements rather than replace them.

### 9.3. Restrict configuration keys

Apply an allowlist of configuration keys that may be modified through the CSV administration module. Do not rely exclusively on request-supplied parameter names to determine which database configuration fields can be updated.

### 9.4. Review related SQL queries

Perform a security review of other application components that construct SQL statements using:

- `$_GET`
- `$_POST`
- `$_REQUEST`
- `$_COOKIE`
- Other externally controlled values

Prioritize queries that concatenate request parameters directly into SQL statements.

### 9.5. Restrict administrative access

Limit access to administrative functionality to authorized users. Apply appropriate authentication, authorization, session management, and network access restrictions.

---

## 10. Detection and Monitoring

Organizations operating affected versions should monitor application and database activity for suspicious behavior associated with the CSV administration functionality. Monitoring should focus on identifying unexpected SQL expressions, unusual configuration changes, and request patterns that may indicate attempts to exploit the vulnerability.

### 10.1. HTTP and application log monitoring

Review web server and application logs for unusual requests involving:

```text
admin/csv_backend.php
```

Pay particular attention to requests using:

```text
action=save
```

Investigate unusual request frequency, unexpected administrative activity, and abnormal response times associated with CSV configuration updates.

**Example Apache access log searches:**

```bash
grep "admin/csv_backend.php" /var/log/apache2/access.log
grep "action=save" /var/log/apache2/access.log
```

These commands identify requests to the endpoint and action when those values are present in the logged request URI.

> **Important:** Standard Apache access logs generally do not record POST request bodies. Therefore, the submitted `CSV_CAT_DEPTH` value may not be visible in ordinary access logs. Detecting the actual POST parameter requires application-level logging, suitable WAF inspection, or another mechanism capable of capturing request bodies. The absence of the parameter in standard access logs does not demonstrate that the parameter was not submitted.

### 10.2. Indicators of Compromise (IoCs)

The following indicators may be useful when investigating potential exploitation attempts:

- **Affected endpoint:** `admin/csv_backend.php`
- **Affected action:** `save`
- **Affected parameter:** `CSV_CAT_DEPTH`

**Suspicious SQL expressions:**

```text
IF(
SLEEP(
```

**Additional patterns to investigate:**

```text
'
#
AND
WHERE
```

*These patterns should be evaluated in context. Their presence alone does not establish malicious activity because some characters and SQL expressions may occur in legitimate application traffic.*

### 10.3. MariaDB Database Monitoring

Review MariaDB logs, particularly the General Query Log when enabled, for suspicious SQL statements associated with CSV configuration updates.

**Monitor for:**

- `UPDATE` statements affecting the `configuration` table that contain unexpected SQL expressions or additional conditions.
- Unexpected use of SQL functions such as `IF()` or `SLEEP()` in statements associated with CSV configuration updates.
- SQL statements containing conditions or clauses that are not part of the expected application query.
- Unexpected modifications to the `CSV_CAT_DEPTH` configuration setting.
- Repeated or unusual updates originating from the CSV administration module.
- Queries in which user-controlled input appears to alter the structure or logic of the original SQL statement.

**Example SQL-related indicators:**

```sql
UPDATE configuration
IF(
SLEEP(
WHERE configuration_key='CSV_CAT_DEPTH'
```

**Example of the query pattern observed during vulnerability validation:**

```sql
UPDATE configuration
SET configuration_value='x'
WHERE configuration_key='CSV_CAT_DEPTH'
AND IF(1=1,SLEEP(5),0) #'
WHERE configuration_key='CSV_CAT_DEPTH'
```

The observed query demonstrates that the supplied `CSV_CAT_DEPTH` value was able to introduce an additional SQL condition and a time-delay function into the database statement.

**Monitoring recommendations:**

- Correlate suspicious database queries with HTTP requests to `admin/csv_backend.php`, particularly requests using the `save` action.
- Review application and database logs for repeated requests or unusual response delays associated with CSV configuration updates.
- Compare modifications to `CSV_CAT_DEPTH` against authorized administrative activity.
- Preserve relevant database and application logs to support incident investigation.

> **Logging considerations:** The MariaDB General Query Log can record executed SQL statements, but it may have performance and storage implications. Enable or configure it according to the organization's monitoring and retention requirements. Standard Apache access logs generally do not record POST request bodies; therefore, identifying the submitted `CSV_CAT_DEPTH` value may require application-level logging, WAF inspection, or another mechanism capable of capturing request bodies. The presence of an individual indicator, such as `IF()` or `SLEEP()`, does not independently prove exploitation. Indicators should be evaluated in the context of the affected endpoint, the associated database query, and the surrounding administrative activity.

### 10.4. Behavioral Correlation

The following sequence may indicate an attempted exploitation:

1. An administrative request reaches `admin/csv_backend.php`.
2. The request uses the `save` action.
3. The application processes a CSV configuration update involving `CSV_CAT_DEPTH`.
4. The database executes an unexpected SQL condition or time-delay function.
5. The corresponding HTTP request exhibits an unusual response delay.
6. The database log records a query containing unexpected SQL expressions.

Correlating these events across application, web server, and database logs can improve detection and incident investigation.

### 10.5. Recommended Monitoring

Organizations should consider implementing:

- Centralized collection of application, web server, and database logs.
- Alerts for unexpected SQL functions in configuration update queries.
- Monitoring of administrative configuration changes.
- Detection of repeated requests associated with the affected endpoint.
- Retention of relevant logs to support forensic analysis.
- WAF rules or equivalent controls to identify suspicious SQL injection patterns.

Detection should be based on multiple correlated indicators whenever possible. An individual log entry or SQL function occurrence should not automatically be classified as a successful exploitation attempt.

---

## 11. Coordinated Vulnerability Disclosure Timeline

| Date | Event |
|---|---|
| November 12, 2026 | Vulnerability validation completed in a controlled laboratory environment. |
| November 12, 2026 | SQL injection behavior corroborated through MariaDB General Query Log analysis. |
| November 12, 2026 | Technical evidence and advisory documentation prepared. |
| November 12, 2026 | Initial vendor notification sent. |
| Pending | Vendor response and remediation status. |

*The timeline will be updated if additional vendor communication or remediation information becomes available.*

---

## 12. Vendor Communication

- **Vendor:** modified eCommerce Shopsoftware Community
- **Repository:** https://github.com/modified-shop/modified-shop
- **Contact Channel:** GitHub Security Advisories / Issues
- **First Notification:** November 12, 2026
- **Current Status:** Notification sent on November 12, 2026. Awaiting response.
- **Coordinated Disclosure Period:** 90 days, following CVD best practices
- **Fixed Version:** Not identified — no validated patch available as of the advisory publication date.

The vendor has been notified of the vulnerability. A 90-day coordinated disclosure period is being observed to provide an opportunity for investigation and remediation. The existence of a fixed version or official patch has not been confirmed.

---

## 13. Credits and Acknowledgments

<div align="center">

<a href="https://github.com/carlosalbertotuma/RedScan_Research_Team"><img src="https://img.shields.io/badge/RedScan-Research%20Team-B22222?style=for-the-badge" alt="RedScan Research Team"></a>

### *RedScan Research Team*

<sub>Offensive Security · Vulnerability Research · Coordinated Disclosure</sub>

| Role | Member |
|:---:|:---:|
| 🏅 **Lead Researcher** | Carlos Tuma ([bl4dsc4n](https://github.com/carlosalbertotuma)) |
| 🏅 **Lead Researcher** | Smith Braz ([smithbraz](https://github.com/smithbraz)) |
| **Researcher** | Anderson Dos Reis Gonzaga |

**Honors**

<sub>Special thanks to <b>Carlos Tuma</b> and <b>Smith Braz</b> for their contribution to the research environment, technical guidance, mentorship, and support throughout the vulnerability validation process.</sub>

<sub>Acknowledgment is also extended to the <a href="https://www.redscanacademy.com.br/">RedScan Academy</a> students and instructors for their contribution to the cybersecurity learning and research community.</sub>

<sub>This research was conducted in a controlled laboratory environment for educational and security research purposes.</sub>

</div>

---

## 14. References

- https://cwe.mitre.org/data/definitions/89.html (CWE-89 — Improper Neutralization of Special Elements used in an SQL Command)
- https://capec.mitre.org/data/definitions/66.html (CAPEC-66 — SQL Injection)
- https://owasp.org/www-community/attacks/SQL_Injection (OWASP — SQL Injection)
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html (OWASP — SQL Injection Prevention Cheat Sheet)
- https://mariadb.com/kb/en/sleep/ (MariaDB Documentation — `SLEEP()`)
- https://github.com/modified-shop/modified-shop (Modified Shop — Official Repository)

---

## 15. Revision History

| Version | Date | Author | Description |
|---|---|---|---|
| 1.0 | November 12, 2026 | Anderson Dos Reis Gonzaga | Initial advisory preparation and technical documentation. |

---

## 16. Legal Notice

This advisory is provided for educational, defensive, and cybersecurity research purposes.

The vulnerability was identified and validated in a controlled laboratory environment. Testing was performed against an environment under the researcher's control.

The information in this document is provided in good faith to help affected parties understand and remediate the reported security issue.

The researcher and research team do not authorize or encourage unauthorized access, exploitation, or disruption of systems.

All product names, trademarks, and registered trademarks mentioned in this document belong to their respective owners.

© 2026 Anderson Dos Reis Gonzaga. All rights reserved.
