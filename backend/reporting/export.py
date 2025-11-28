"""
Report Export Module
Handles exporting vulnerability reports in various formats
"""

import json
import os
from typing import Dict, Any


class ReportExporter:
    """
    Handles exporting reports in various formats
    """

    def export(self, report: Dict[str, Any], format: str = 'json', scan_id: str = '') -> str:
        """
        Export report in specified format
        
        Args:
            report: The report data to export
            format: The format to export in (json, html, pdf, markdown, docx)
            scan_id: The scan ID (used for filename)
            
        Returns:
            Path to the exported file
        """
        # Create exports directory if it doesn't exist
        exports_dir = os.path.join(os.getcwd(), 'exports')
        os.makedirs(exports_dir, exist_ok=True)
        
        if format.lower() == 'json':
            return self._export_json(report, scan_id, exports_dir)
        elif format.lower() == 'html':
            return self._export_html(report, scan_id, exports_dir)
        elif format.lower() == 'markdown':
            return self._export_markdown(report, scan_id, exports_dir)
        else:
            # Default to JSON for unsupported formats
            return self._export_json(report, scan_id, exports_dir)

    def _export_json(self, report: Dict[str, Any], scan_id: str, exports_dir: str) -> str:
        """
        Export report as JSON
        """
        filename = f"optimus_report_{scan_id}.json"
        filepath = os.path.join(exports_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
            
        return filepath

    def _export_html(self, report: Dict[str, Any], scan_id: str, exports_dir: str) -> str:
        """
        Export report as HTML
        """
        filename = f"optimus_report_{scan_id}.html"
        filepath = os.path.join(exports_dir, filename)
        
        html_content = self._generate_html_report(report)
        
        with open(filepath, 'w') as f:
            f.write(html_content)
            
        return filepath

    def _export_markdown(self, report: Dict[str, Any], scan_id: str, exports_dir: str) -> str:
        """
        Export report as Markdown
        """
        filename = f"optimus_report_{scan_id}.md"
        filepath = os.path.join(exports_dir, filename)
        
        markdown_content = self._generate_markdown_report(report)
        
        with open(filepath, 'w') as f:
            f.write(markdown_content)
            
        return filepath

    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """
        Generate HTML report content
        """
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Optimus Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2, h3 {{ color: #333; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary-stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ background-color: #e0e0e0; padding: 15px; border-radius: 5px; text-align: center; }}
        .vulnerabilities {{ margin-top: 30px; }}
        .vuln-item {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .severity-critical {{ border-left: 5px solid #d9534f; }}
        .severity-high {{ border-left: 5px solid #f0ad4e; }}
        .severity-medium {{ border-left: 5px solid #5bc0de; }}
        .severity-low {{ border-left: 5px solid #5cb85c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Optimus Security Scan Report</h1>
        <p>Target: {report['metadata']['target']}</p>
        <p>Scan ID: {report['metadata']['scan_id']}</p>
        <p>Generated: {report['metadata']['generated_at']}</p>
    </div>
    
    <div class="summary-stats">
        <div class="stat-box">
            <h3>Total Findings</h3>
            <p>{report['executive_summary']['total_findings']}</p>
        </div>
        <div class="stat-box">
            <h3>Critical</h3>
            <p>{report['executive_summary']['critical_vulnerabilities']}</p>
        </div>
        <div class="stat-box">
            <h3>High</h3>
            <p>{report['executive_summary']['high_vulnerabilities']}</p>
        </div>
        <div class="stat-box">
            <h3>Medium</h3>
            <p>{report['executive_summary']['medium_vulnerabilities']}</p>
        </div>
        <div class="stat-box">
            <h3>Low</h3>
            <p>{report['executive_summary']['low_vulnerabilities']}</p>
        </div>
    </div>
    
    <div class="vulnerabilities">
        <h2>Vulnerabilities</h2>
        """
        
        for vuln in report['vulnerabilities']:
            severity_class = f"severity-{vuln['severity'].lower()}"
            html += f"""
        <div class="vuln-item {severity_class}">
            <h3>{vuln['title']} ({vuln['severity']})</h3>
            <p><strong>CVSS Score:</strong> {vuln['cvss_score']}</p>
            <p><strong>Description:</strong> {vuln['description']}</p>
            <p><strong>Location:</strong> {vuln['technical_details'].get('location', 'N/A')}</p>
        </div>
            """
        
        html += """
    </div>
</body>
</html>
        """
        
        return html

    def _generate_markdown_report(self, report: Dict[str, Any]) -> str:
        """
        Generate Markdown report content
        """
        md = f"""# Optimus Security Scan Report

## Scan Information
- **Target:** {report['metadata']['target']}
- **Scan ID:** {report['metadata']['scan_id']}
- **Generated:** {report['metadata']['generated_at']}

## Executive Summary
{report['executive_summary']['summary_text']}

## Summary Statistics
| Total Findings | Critical | High | Medium | Low |
|---------------|----------|------|--------|-----|
| {report['executive_summary']['total_findings']} | {report['executive_summary']['critical_vulnerabilities']} | {report['executive_summary']['high_vulnerabilities']} | {report['executive_summary']['medium_vulnerabilities']} | {report['executive_summary']['low_vulnerabilities']} |

## Vulnerabilities

"""
        
        for vuln in report['vulnerabilities']:
            md += f"""### {vuln['title']} ({vuln['severity']})

- **CVSS Score:** {vuln['cvss_score']}
- **Description:** {vuln['description']}
- **Location:** {vuln['technical_details'].get('location', 'N/A')}

"""
        
        return md