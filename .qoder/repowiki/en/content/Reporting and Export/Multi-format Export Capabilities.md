# Multi-format Export Capabilities

<cite>
**Referenced Files in This Document**
- [export.py](file://backend/reporting/export.py)
- [professional_report.py](file://backend/reporting/professional_report.py)
- [report_generator.py](file://backend/reporting/report_generator.py)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py)
- [report_routes.py](file://backend/api/report_routes.py)
- [app.py](file://backend/app.py)
- [full_report.html](file://backend/reporting/templates/full_report.html)
- [pdf_cover.html](file://backend/reporting/templates/pdf_cover.html)
- [executive_summary.html](file://backend/reporting/templates/executive_summary.html)
- [vulnerability_detail.html](file://backend/reporting/templates/vulnerability_detail.html)
- [api.ts](file://frontend/src/services/api.ts)
- [Reports.tsx](file://frontend/src/pages/Reports.tsx)
</cite>

## Table of Contents
1. [Introduction](#introduction)
2. [Project Structure](#project-structure)
3. [Core Components](#core-components)
4. [Architecture Overview](#architecture-overview)
5. [Detailed Component Analysis](#detailed-component-analysis)
6. [Dependency Analysis](#dependency-analysis)
7. [Performance Considerations](#performance-considerations)
8. [Troubleshooting Guide](#troubleshooting-guide)
9. [Conclusion](#conclusion)

## Introduction
This document explains the multi-format export capabilities of the Optimus platform, focusing on how reports are generated, transformed, and delivered in multiple formats. It covers the export module implementation for JSON and HTML, the professional report generation system for polished stakeholder-ready documentation, and the integration points with the frontend and backend. It also documents configuration options, format-specific processing, quality assurance measures, and practical examples for customization, batch generation, and automated delivery workflows.

## Project Structure
The export system spans backend reporting modules, API routes, HTML templates, and frontend services. The backend orchestrates report generation and export, while the frontend provides user-driven export actions and downloads.

```mermaid
graph TB
subgraph "Frontend"
FE_API["api.ts<br/>Reports API client"]
FE_UI["Reports.tsx<br/>Export UI actions"]
end
subgraph "Backend"
APP["app.py<br/>Flask app + blueprints"]
ROUTES["report_routes.py<br/>/api/reports endpoints"]
GEN["report_generator.py<br/>VulnerabilityReportGenerator"]
PRO_GEN["professional_report.py<br/>ProfessionalReportGenerator"]
INT_GEN["intelligent_reporter.py<br/>IntelligentReportGenerator"]
EXPORT["export.py<br/>ReportExporter"]
TPL_FULL["full_report.html"]
TPL_COVER["pdf_cover.html"]
TPL_EXEC["executive_summary.html"]
TPL_VULN["vulnerability_detail.html"]
end
FE_API --> FE_UI
FE_UI --> FE_API
FE_API --> ROUTES
ROUTES --> GEN
ROUTES --> PRO_GEN
ROUTES --> INT_GEN
ROUTES --> EXPORT
GEN --> TPL_FULL
PRO_GEN --> TPL_COVER
PRO_GEN --> TPL_EXEC
PRO_GEN --> TPL_VULN
EXPORT --> TPL_FULL
EXPORT --> TPL_EXEC
EXPORT --> TPL_VULN
APP --> ROUTES
```

**Diagram sources**
- [app.py](file://backend/app.py#L200-L220)
- [report_routes.py](file://backend/api/report_routes.py#L33-L81)
- [report_generator.py](file://backend/reporting/report_generator.py#L14-L42)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L99)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L160)
- [export.py](file://backend/reporting/export.py#L11-L41)
- [full_report.html](file://backend/reporting/templates/full_report.html#L1-L230)
- [pdf_cover.html](file://backend/reporting/templates/pdf_cover.html#L1-L64)
- [executive_summary.html](file://backend/reporting/templates/executive_summary.html#L1-L170)
- [vulnerability_detail.html](file://backend/reporting/templates/vulnerability_detail.html#L1-L247)

**Section sources**
- [app.py](file://backend/app.py#L200-L220)
- [report_routes.py](file://backend/api/report_routes.py#L33-L81)

## Core Components
- ReportExporter: Provides export functionality for JSON, HTML, and Markdown formats. It writes files to a standardized exports directory and returns the file path.
- VulnerabilityReportGenerator: Creates detailed vulnerability reports with metadata, executive summary, vulnerability entries, attack chains, and recommendations.
- ProfessionalReportGenerator: Produces structured, stakeholder-ready penetration test reports with executive summaries, risk assessments, remediation guidance, and appendices.
- IntelligentReportGenerator: Uses LLMs to generate AI-enhanced executive summaries, prioritize remediation items, and produce strategic recommendations.
- Template System: HTML templates define the structure and styling for professional report formatting across different sections (cover, executive summary, full report, vulnerability detail).
- API Routes: Expose endpoints to generate and download reports, integrating with the generators and exporters.
- Frontend Services: Provide user-triggered export actions and handle file downloads.

**Section sources**
- [export.py](file://backend/reporting/export.py#L11-L81)
- [report_generator.py](file://backend/reporting/report_generator.py#L14-L42)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L99)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L160)
- [report_routes.py](file://backend/api/report_routes.py#L35-L81)
- [api.ts](file://frontend/src/services/api.ts#L237-L272)
- [Reports.tsx](file://frontend/src/pages/Reports.tsx#L267-L283)

## Architecture Overview
The export pipeline integrates frontend user actions, backend API routes, report generators, and template rendering to produce multi-format outputs.

```mermaid
sequenceDiagram
participant UI as "Frontend UI (Reports.tsx)"
participant API as "Frontend API (api.ts)"
participant Routes as "Report Routes (report_routes.py)"
participant Gen as "Report Generators"
participant Export as "ReportExporter"
participant FS as "File System"
UI->>API : Trigger export(format)
API->>Routes : GET /api/reports/download/{scan_id}/{format}
Routes->>Gen : Generate report (JSON/HTML)
alt JSON export
Routes->>FS : Write JSON to temp path
Routes-->>API : send_file(JSON)
API-->>UI : Blob download
else HTML export
Routes->>Export : export(report, html, scan_id)
Export->>FS : Write HTML to exports/
Export-->>Routes : File path
Routes-->>API : send_file(HTML)
API-->>UI : Blob download
end
```

**Diagram sources**
- [Reports.tsx](file://frontend/src/pages/Reports.tsx#L267-L283)
- [api.ts](file://frontend/src/services/api.ts#L257-L263)
- [report_routes.py](file://backend/api/report_routes.py#L50-L81)
- [export.py](file://backend/reporting/export.py#L16-L41)

## Detailed Component Analysis

### ReportExporter: Multi-format Export Engine
The exporter supports JSON, HTML, and Markdown exports. It validates the requested format and falls back to JSON for unsupported formats. It writes files to a dedicated exports directory and returns the file path.

```mermaid
classDiagram
class ReportExporter {
+export(report, format, scan_id) str
-_export_json(report, scan_id, exports_dir) str
-_export_html(report, scan_id, exports_dir) str
-_export_markdown(report, scan_id, exports_dir) str
-_generate_html_report(report) str
-_generate_markdown_report(report) str
}
```

**Diagram sources**
- [export.py](file://backend/reporting/export.py#L11-L81)

**Section sources**
- [export.py](file://backend/reporting/export.py#L16-L81)

### VulnerabilityReportGenerator: Detailed Report Builder
Generates comprehensive reports with metadata, executive summary, vulnerability entries, attack chains, and recommendations. It maps findings to CWE/OWASP categories and produces structured data for downstream export.

```mermaid
classDiagram
class VulnerabilityReportGenerator {
+generate_detailed_report(scan_state) Dict
-_generate_metadata(scan_state) Dict
-_generate_executive_summary(scan_state) Dict
-_generate_vulnerability_entry(finding) Dict
-_calculate_severity_rating(finding) str
-_map_to_cwe(finding) str
-_map_to_owasp(finding) str
-_generate_description(finding) str
-_generate_reproduction_steps(finding) str[]
-_generate_poc(finding) Dict
-_analyze_impact(finding) Dict
-_generate_remediation(finding) Dict
-_get_references(finding) Dict[]
-_reconstruct_attack_chain(scan_state) Dict[]
-_generate_recommendations(scan_state) Dict[]
}
```

**Diagram sources**
- [report_generator.py](file://backend/reporting/report_generator.py#L14-L438)

**Section sources**
- [report_generator.py](file://backend/reporting/report_generator.py#L19-L42)

### ProfessionalReportGenerator: Stakeholder-ready Reports
Produces polished, structured penetration test reports with executive summaries, risk assessments, remediation guidance, and appendices. It saves reports to a configurable output directory and includes professional formatting via HTML templates.

```mermaid
classDiagram
class ProfessionalReportGenerator {
+generate_report(scan_state) Dict
+save_report(report, format) str
-_generate_report_info(scan_state) Dict
-_generate_executive_summary(scan_state) Dict
-_get_key_findings(findings) str[]
-_get_immediate_actions(findings) str[]
-_generate_scope(scan_state) Dict
-_generate_methodology(scan_state) Dict
-_generate_findings_summary(scan_state) Dict
-_generate_detailed_findings(scan_state) Dict[]
-_create_detailed_finding(finding, index, scan_state) Dict
-_generate_description(finding) str
-_generate_reproduction_steps(finding, scan_state) str[]
-_generate_impact(finding) Dict
-_generate_remediation(finding) Dict
-_get_references(vuln_type) str[]
-_generate_exploitation_results(scan_state) Dict
-_generate_risk_assessment(scan_state) Dict
-_generate_recommendations(scan_state) Dict[]
-_generate_appendix(scan_state) Dict
-_severity_to_label(score) str
-_truncate(text, length) str
}
```

**Diagram sources**
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L715)

**Section sources**
- [professional_report.py](file://backend/reporting/professional_report.py#L82-L99)

### IntelligentReportGenerator: AI-enhanced Reports
Enhances reports with LLM-generated executive summaries, prioritized remediation plans, risk scoring, and strategic recommendations. It includes fallback logic when LLM is unavailable.

```mermaid
classDiagram
class IntelligentReportGenerator {
+generate_report(scan_state) IntelligentReport
-_count_by_severity(findings) Dict~str,int~
-_calculate_risk_score(findings) float
-_get_risk_rating(score) str
-_generate_remediation_plan(findings) RemediationItem[]
-_get_numeric_severity(sev) float
-_get_remediation_title(vuln_type) str
-_get_remediation_description(vuln_type) str
-_estimate_effort(vuln_type) str
-_estimate_impact(severity) str
-_get_recommended_action(vuln_type) str
-_get_remediation_references(vuln_type) str[]
-_extract_key_findings(findings) str[]
-_generate_executive_summary(scan_state, findings, counts, risk_score) str
-_generate_llm_summary(scan_state, findings, counts, risk_score) str
-_generate_template_summary(scan_state, findings, counts, risk_score) str
-_analyze_attack_chains(findings, scan_state) Dict[]
-_generate_strategic_recommendations(findings, scan_state) str[]
}
class RemediationItem {
+priority : str
+title : str
+description : str
+affected_assets : str[]
+cve_ids : str[]
+effort : str
+impact : str
+recommended_action : str
+references : str[]
}
IntelligentReportGenerator --> RemediationItem : "creates"
```

**Diagram sources**
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L555)

**Section sources**
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L102-L160)

### Template System: Professional Formatting
HTML templates define the structure and styling for professional report formatting. They include sections for covers, executive summaries, full reports, and vulnerability details, enabling consistent presentation across formats.

```mermaid
graph TB
TPL_FULL["full_report.html<br/>Full report layout"]
TPL_COVER["pdf_cover.html<br/>Cover page"]
TPL_EXEC["executive_summary.html<br/>Executive summary"]
TPL_VULN["vulnerability_detail.html<br/>Vulnerability detail"]
TPL_FULL --> |"Used by"| PRO_GEN["ProfessionalReportGenerator"]
TPL_COVER --> |"Used by"| PRO_GEN
TPL_EXEC --> |"Used by"| PRO_GEN
TPL_VULN --> |"Used by"| PRO_GEN
```

**Diagram sources**
- [full_report.html](file://backend/reporting/templates/full_report.html#L1-L230)
- [pdf_cover.html](file://backend/reporting/templates/pdf_cover.html#L1-L64)
- [executive_summary.html](file://backend/reporting/templates/executive_summary.html#L1-L170)
- [vulnerability_detail.html](file://backend/reporting/templates/vulnerability_detail.html#L1-L247)

**Section sources**
- [full_report.html](file://backend/reporting/templates/full_report.html#L1-L230)
- [pdf_cover.html](file://backend/reporting/templates/pdf_cover.html#L1-L64)
- [executive_summary.html](file://backend/reporting/templates/executive_summary.html#L1-L170)
- [vulnerability_detail.html](file://backend/reporting/templates/vulnerability_detail.html#L1-L247)

### API Integration: Generation and Download
The report routes integrate with the generators and exporters to serve JSON and HTML reports. The frontend invokes these endpoints to download files.

```mermaid
sequenceDiagram
participant FE as "Frontend"
participant API as "api.ts"
participant BP as "report_routes.py"
participant GEN as "VulnerabilityReportGenerator"
participant EXP as "ReportExporter"
FE->>API : reports.download(scanId, format)
API->>BP : GET /api/reports/download/{scan_id}/{format}
BP->>GEN : generate_detailed_report(scan)
alt format == json
BP-->>API : send_file(JSON)
else format == html
BP->>EXP : export(report, html, scan_id)
EXP-->>BP : file path
BP-->>API : send_file(HTML)
end
API-->>FE : Blob download
```

**Diagram sources**
- [api.ts](file://frontend/src/services/api.ts#L257-L263)
- [report_routes.py](file://backend/api/report_routes.py#L50-L81)
- [export.py](file://backend/reporting/export.py#L16-L41)

**Section sources**
- [report_routes.py](file://backend/api/report_routes.py#L35-L81)
- [api.ts](file://frontend/src/services/api.ts#L257-L263)

## Dependency Analysis
The export system relies on a layered architecture: frontend services call backend routes, which orchestrate report generation and optional export processing, then deliver files to clients.

```mermaid
graph LR
FE["frontend/src/services/api.ts"] --> RT["backend/api/report_routes.py"]
RT --> VG["backend/reporting/report_generator.py"]
RT --> PG["backend/reporting/professional_report.py"]
RT --> IG["backend/reporting/intelligent_reporter.py"]
RT --> EX["backend/reporting/export.py"]
EX --> TPL["backend/reporting/templates/*.html"]
APP["backend/app.py"] --> RT
```

**Diagram sources**
- [api.ts](file://frontend/src/services/api.ts#L237-L272)
- [report_routes.py](file://backend/api/report_routes.py#L33-L81)
- [report_generator.py](file://backend/reporting/report_generator.py#L14-L42)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L99)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L160)
- [export.py](file://backend/reporting/export.py#L11-L41)
- [app.py](file://backend/app.py#L200-L220)

**Section sources**
- [app.py](file://backend/app.py#L200-L220)
- [report_routes.py](file://backend/api/report_routes.py#L33-L81)

## Performance Considerations
- Large report handling: For very large scans, consider streaming JSON or chunked HTML generation to reduce memory usage during export.
- Template rendering: HTML generation uses string concatenation and Jinja-style templating; keep templates modular and avoid excessive DOM nesting for large vulnerability lists.
- Disk I/O: Writing to disk introduces latency; cache frequently accessed reports or use in-memory buffers for small exports.
- Concurrency: The Flask app runs single-threaded by default; for high-throughput scenarios, enable asynchronous workers or offload heavy processing to background tasks.
- Network transfer: For large binary downloads, consider compression or segmented transfers.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and resolutions:
- Unsupported format: The exporter defaults to JSON for unsupported formats. Ensure the requested format matches supported values.
- Missing scan data: API routes return 404 if scan_id is not found in active scans or history.
- LLM unavailability: IntelligentReportGenerator falls back to template-based summaries when LLM is not available.
- File permissions: Ensure the exports directory exists and is writable; the exporter creates it automatically.
- Encoding issues: The backend enforces UTF-8 logging and safe formatting on Windows; verify environment variables and file encodings.

**Section sources**
- [export.py](file://backend/reporting/export.py#L38-L40)
- [report_routes.py](file://backend/api/report_routes.py#L41-L43)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L398-L405)

## Conclusion
The Optimus export system provides a flexible, extensible foundation for generating multi-format reports. It integrates detailed vulnerability data with professional formatting and AI-enhanced insights, supporting both developer-focused JSON exports and stakeholder-ready HTML outputs. By leveraging the provided generators, templates, and API routes, teams can customize report content, automate delivery workflows, and maintain high-quality outputs across diverse use cases.