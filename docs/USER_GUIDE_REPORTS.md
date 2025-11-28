# Optimus Reporting User Guide

## Overview

Optimus generates comprehensive security reports with detailed vulnerability analysis, step-by-step reproduction instructions, and professional remediation guidance. Reports are available in multiple formats for different audiences and use cases.

## Viewing Reports in the Dashboard

### Accessing Reports

1. Navigate to the **Scan Results** page after a scan completes
2. Click the **"View Detailed Report"** button to access the full report dashboard
3. Alternatively, you can access reports directly via the URL: `/report/{scan_id}`

### Report Dashboard Features

The report dashboard provides a comprehensive view of scan findings:

#### Executive Summary Section

- **Risk Score Gauge**: Visual representation of overall security posture
- **Vulnerability Breakdown**: Pie chart showing distribution by severity
- **Severity Distribution**: Bar chart of findings by criticality
- **Key Metrics**: Total findings, tools used, scan duration

#### Vulnerability Table

- **Sortable Columns**: Click column headers to sort by severity, type, or location
- **Filtering**: Filter by severity level or vulnerability type
- **Expandable Details**: Click any row to view detailed vulnerability information
- **Color Coding**: Red (critical), orange (high), yellow (medium), blue (low)

#### Detailed Vulnerability View

When you click on a vulnerability in the table, a detailed view opens with:

##### Header Information

- Vulnerability title
- Severity badge with color coding
- CVSS score
- CWE/OWASP tags

##### Description Tab

- What the vulnerability is
- Why it's dangerous
- Affected component

##### Reproduction Tab

- Step-by-step instructions for manual verification
- Numbered list of actions
- Code snippets with syntax highlighting
- Screenshots/evidence (when available)
- Video tutorial links (if configured)

##### Impact Tab

- What an attacker can do with this vulnerability
- Business impact assessment
- Compliance violations (GDPR, PCI-DSS, etc.)

##### Remediation Tab

- How to fix the issue (code changes)
- Configuration changes
- Best practices
- Time estimate for remediation

##### References Tab

- CVE links
- CWE links
- OWASP links
- Related articles and resources

## Downloading Reports

### Available Formats

Optimus supports multiple report formats for different needs:

- **PDF**: Professional format for executive presentations and client delivery
- **HTML**: Interactive web format for easy browsing and sharing
- **JSON**: Machine-readable format for integration with other tools
- **Markdown**: Plain text format for documentation and version control
- **DOCX**: Microsoft Word format for formal reporting

### Download Process

1. On the report dashboard, locate the **"Report Actions"** section
2. Click the appropriate download button for your desired format:
   - **Download PDF Report**
   - **Download JSON Report**
   - **Download HTML Report**
   - **Download Markdown Report**
   - **Download DOCX Report**
3. Your browser will prompt you to save the file

## Understanding Vulnerability Details

### Severity Ratings

Vulnerabilities are classified by severity:

- **Critical** (9.0-10.0): Immediate threat, requires urgent attention
- **High** (7.0-8.9): Significant risk, should be addressed promptly
- **Medium** (4.0-6.9): Moderate risk, should be addressed in due course
- **Low** (0.1-3.9): Minimal risk, can be addressed as convenient

### CVSS Scores

The Common Vulnerability Scoring System (CVSS) provides a numerical risk assessment:

- **Base Score**: Intrinsic characteristics that are constant over time
- **Temporal Score**: Characteristics that change over time
- **Environmental Score**: Characteristics that are unique to a user's environment

### CWE and OWASP Mapping

Each vulnerability is mapped to industry standards:

- **CWE**: Common Weakness Enumeration identifiers
- **OWASP**: Open Web Application Security Project categories

## Following Reproduction Steps

### Purpose

Reproduction steps allow security teams to:

- Verify that reported vulnerabilities are genuine
- Understand the exact conditions that lead to exploitation
- Demonstrate the issue to developers or stakeholders

### Process

1. **Preparation**: Ensure you have the required tools and access
2. **Environment Setup**: Configure the target environment as described
3. **Step Execution**: Follow each numbered step precisely
4. **Verification**: Confirm that the expected outcome occurs
5. **Documentation**: Record your findings and any variations

### Tips

- Always test in a controlled environment
- Ensure you have proper authorization before testing
- Document any deviations from the prescribed steps
- Take screenshots or videos for evidence

## Using Remediation Guidance

### Code Fixes

Remediation guidance includes specific code changes:

- **Before/After Examples**: Clear illustrations of the problem and solution
- **Language-Specific Solutions**: Guidance tailored to your technology stack
- **Framework-Aware Fixes**: Recommendations for Django, Flask, React, etc.

### Configuration Changes

Some vulnerabilities can be addressed through configuration:

- **Server Settings**: Web server, application server, or database configurations
- **Security Headers**: HTTP headers that enhance protection
- **Access Controls**: Permission settings and authentication configurations

### Best Practices

Long-term security improvements:

- **Secure Coding Guidelines**: Principles to prevent similar issues
- **Architecture Recommendations**: Design patterns that reduce risk
- **Monitoring Suggestions**: Ways to detect exploitation attempts

## Interpreting Severity Ratings

### Critical Vulnerabilities

Require immediate attention because:

- They can be exploited remotely without authentication
- They allow full system compromise
- They expose sensitive data to unauthorized parties
- They can cause significant business disruption

### High Vulnerabilities

Should be addressed quickly because:

- They can lead to significant data loss or system compromise
- They may require minimal user interaction to exploit
- They affect core business functions
- They violate compliance requirements

### Medium Vulnerabilities

Should be addressed in due course because:

- They pose a moderate risk to system security
- They may require specific conditions to exploit
- They could be combined with other vulnerabilities for greater impact
- They affect non-critical system functions

### Low Vulnerabilities

Can be addressed as convenient because:

- They pose minimal risk to system security
- They require significant user interaction to exploit
- They affect non-sensitive system functions
- They are primarily informational in nature

## FAQ

### Why are some vulnerabilities marked as "Informational"?

Informational findings highlight security best practices or potential issues that don't directly constitute vulnerabilities. They're included to help improve overall security posture.

### How are severity scores calculated?

Severity scores are based on the CVSS framework, considering factors like exploitability, impact, and required access level. Our system also incorporates contextual factors specific to your environment.

### Can I customize the report format?

Yes, the reporting system is template-based and can be customized to meet your organization's specific requirements. Contact your administrator for customization options.

### How often are reports updated?

Reports are generated at the conclusion of each scan. Historical reports are retained for comparison and trend analysis.

### Can I share reports with external parties?

Yes, reports can be shared with external parties. Consider using the PDF or DOCX formats for professional presentation. Be sure to redact any sensitive information before sharing.

## Troubleshooting

### Report Generation Fails

- Check that the scan completed successfully
- Verify that there is sufficient disk space for report generation
- Ensure that required dependencies are installed

### Download Links Not Working

- Verify that your browser allows file downloads
- Check that the report file was generated successfully
- Try refreshing the page and attempting the download again

### Missing Vulnerability Details

- Ensure that the scan had sufficient time to complete all tests
- Check that all required tools were available during the scan
- Verify that the target was accessible throughout the scan

## Support

For assistance with reporting features, contact:

- **Email**: support@optimus-security.com
- **Documentation**: https://docs.optimus-security.com
- **Community Forum**: https://community.optimus-security.com

Our support team is available Monday-Friday, 9AM-5PM EST.