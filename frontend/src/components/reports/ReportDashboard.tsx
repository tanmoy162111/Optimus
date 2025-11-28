import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useWebSocket } from '../../hooks/useWebSocket';

interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  cvss_score: number;
  description: string;
  reproduction_steps: string[];
  technical_details: {
    location?: string;
    parameter?: string;
    method?: string;
    payload?: string;
  };
  remediation: {
    immediate: string;
    long_term: string;
    code_example: string;
  };
}

interface ReportData {
  metadata: {
    report_id: string;
    scan_id: string;
    target: string;
    generated_at: string;
    tools_used: string[];
    duration_seconds: number;
    coverage_percentage: number;
  };
  executive_summary: {
    risk_level: string;
    total_findings: number;
    critical_vulnerabilities: number;
    high_vulnerabilities: number;
    medium_vulnerabilities: number;
    low_vulnerabilities: number;
    summary_text: string;
  };
  vulnerabilities: Vulnerability[];
  attack_chain: any[];
  recommendations: any[];
}

const ReportDashboard: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [reportData, setReportData] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  // Fetch report data
  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        // In a real implementation, this would call the backend API
        // const response = await fetch(`/api/report/generate/${scanId}`);
        // const data = await response.json();
        
        // Mock data for demonstration
        const mockData: ReportData = {
          metadata: {
            report_id: 'mock-report-id',
            scan_id: scanId || '',
            target: 'http://example.com',
            generated_at: new Date().toISOString(),
            tools_used: ['nmap', 'nikto', 'sqlmap'],
            duration_seconds: 300,
            coverage_percentage: 75
          },
          executive_summary: {
            risk_level: 'High',
            total_findings: 12,
            critical_vulnerabilities: 1,
            high_vulnerabilities: 3,
            medium_vulnerabilities: 5,
            low_vulnerabilities: 3,
            summary_text: 'Security scan identified 12 vulnerabilities, including 1 critical and 3 high severity issues.'
          },
          vulnerabilities: [
            {
              id: 'vuln-1',
              title: 'SQL Injection',
              severity: 'Critical',
              cvss_score: 9.8,
              description: 'The application is vulnerable to SQL injection attacks.',
              reproduction_steps: [
                'Navigate to the vulnerable endpoint',
                'Identify the vulnerable parameter',
                'Submit the SQL injection payload',
                'Observe the SQL error in the response'
              ],
              technical_details: {
                location: 'http://example.com/login',
                parameter: 'username',
                method: 'POST',
                payload: "' OR '1'='1"
              },
              remediation: {
                immediate: 'Implement parameterized queries',
                long_term: 'Use ORM frameworks and input validation',
                code_example: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
              }
            },
            {
              id: 'vuln-2',
              title: 'Cross-Site Scripting (XSS)',
              severity: 'High',
              cvss_score: 7.2,
              description: 'The application does not properly sanitize user input.',
              reproduction_steps: [
                'Open the target URL',
                'Locate the input field',
                'Input the XSS payload',
                'Submit the form',
                'Observe JavaScript execution'
              ],
              technical_details: {
                location: 'http://example.com/search',
                parameter: 'q',
                method: 'GET',
                payload: '<script>alert("XSS")</script>'
              },
              remediation: {
                immediate: 'Implement proper input sanitization',
                long_term: 'Use Content Security Policy (CSP)',
                code_example: 'from html import escape\nsafe_output = escape(user_input)'
              }
            }
          ],
          attack_chain: [],
          recommendations: []
        };
        
        setReportData(mockData);
      } catch (err) {
        setError('Failed to load report data');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    if (scanId) {
      fetchReport();
    }
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
        <strong className="font-bold">Error: </strong>
        <span className="block sm:inline">{error}</span>
      </div>
    );
  }

  if (!reportData) {
    return <div>No report data available</div>;
  }

  const severityColors: Record<string, string> = {
    Critical: 'bg-red-500 text-white',
    High: 'bg-orange-500 text-white',
    Medium: 'bg-yellow-500 text-black',
    Low: 'bg-green-500 text-white'
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-800 mb-2">Security Scan Report</h1>
        <p className="text-gray-600">Scan ID: {reportData.metadata.scan_id}</p>
        <p className="text-gray-600">Target: {reportData.metadata.target}</p>
      </div>

      {/* Executive Summary */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-8">
        <h2 className="text-2xl font-semibold mb-4">Executive Summary</h2>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-4">
          <div className="bg-red-100 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-red-600">{reportData.executive_summary.critical_vulnerabilities}</div>
            <div className="text-sm text-gray-600">Critical</div>
          </div>
          <div className="bg-orange-100 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-orange-600">{reportData.executive_summary.high_vulnerabilities}</div>
            <div className="text-sm text-gray-600">High</div>
          </div>
          <div className="bg-yellow-100 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-yellow-600">{reportData.executive_summary.medium_vulnerabilities}</div>
            <div className="text-sm text-gray-600">Medium</div>
          </div>
          <div className="bg-green-100 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-green-600">{reportData.executive_summary.low_vulnerabilities}</div>
            <div className="text-sm text-gray-600">Low</div>
          </div>
          <div className="bg-blue-100 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-blue-600">{reportData.executive_summary.total_findings}</div>
            <div className="text-sm text-gray-600">Total</div>
          </div>
        </div>
        <div className="mb-4">
          <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
            reportData.executive_summary.risk_level === 'Critical' ? 'bg-red-500 text-white' :
            reportData.executive_summary.risk_level === 'High' ? 'bg-orange-500 text-white' :
            reportData.executive_summary.risk_level === 'Medium' ? 'bg-yellow-500 text-black' :
            'bg-green-500 text-white'
          }`}>
            Risk Level: {reportData.executive_summary.risk_level}
          </span>
        </div>
        <p className="text-gray-700">{reportData.executive_summary.summary_text}</p>
      </div>

      {/* Vulnerabilities Table */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-8">
        <h2 className="text-2xl font-semibold mb-4">Vulnerabilities</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white">
            <thead>
              <tr className="bg-gray-100">
                <th className="py-2 px-4 text-left">Title</th>
                <th className="py-2 px-4 text-left">Severity</th>
                <th className="py-2 px-4 text-left">CVSS Score</th>
                <th className="py-2 px-4 text-left">Location</th>
              </tr>
            </thead>
            <tbody>
              {reportData.vulnerabilities.map((vuln) => (
                <tr 
                  key={vuln.id} 
                  className="border-b hover:bg-gray-50 cursor-pointer"
                  onClick={() => setSelectedVulnerability(vuln)}
                >
                  <td className="py-2 px-4">{vuln.title}</td>
                  <td className="py-2 px-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${severityColors[vuln.severity]}`}>
                      {vuln.severity}
                    </span>
                  </td>
                  <td className="py-2 px-4">{vuln.cvss_score}</td>
                  <td className="py-2 px-4">{vuln.technical_details.location || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Vulnerability Detail Modal */}
      {selectedVulnerability && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-screen overflow-y-auto">
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <h3 className="text-2xl font-bold">{selectedVulnerability.title}</h3>
                <button 
                  onClick={() => setSelectedVulnerability(null)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              
              <div className="mb-4">
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${severityColors[selectedVulnerability.severity]}`}>
                  {selectedVulnerability.severity} (CVSS: {selectedVulnerability.cvss_score})
                </span>
              </div>
              
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-2">Description</h4>
                <p className="text-gray-700">{selectedVulnerability.description}</p>
              </div>
              
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-2">Reproduction Steps</h4>
                <ol className="list-decimal list-inside space-y-2">
                  {selectedVulnerability.reproduction_steps.map((step, index) => (
                    <li key={index} className="text-gray-700">{step}</li>
                  ))}
                </ol>
              </div>
              
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-2">Technical Details</h4>
                <div className="bg-gray-100 p-4 rounded">
                  <p><strong>Location:</strong> {selectedVulnerability.technical_details.location || 'N/A'}</p>
                  <p><strong>Parameter:</strong> {selectedVulnerability.technical_details.parameter || 'N/A'}</p>
                  <p><strong>Method:</strong> {selectedVulnerability.technical_details.method || 'N/A'}</p>
                  <p><strong>Payload:</strong> <code className="bg-gray-200 px-1 rounded">{selectedVulnerability.technical_details.payload || 'N/A'}</code></p>
                </div>
              </div>
              
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-2">Remediation</h4>
                <p className="mb-2"><strong>Immediate:</strong> {selectedVulnerability.remediation.immediate}</p>
                <p className="mb-2"><strong>Long-term:</strong> {selectedVulnerability.remediation.long_term}</p>
                <div className="bg-gray-100 p-4 rounded">
                  <pre className="whitespace-pre-wrap">{selectedVulnerability.remediation.code_example}</pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Report Actions */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-2xl font-semibold mb-4">Report Actions</h2>
        <div className="flex flex-wrap gap-4">
          <button className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded">
            Download PDF Report
          </button>
          <button className="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded">
            Download JSON Report
          </button>
          <button className="bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded">
            Share Report
          </button>
        </div>
      </div>
    </div>
  );
};

export default ReportDashboard;