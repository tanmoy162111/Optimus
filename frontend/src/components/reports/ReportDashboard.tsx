import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../../services/api';
import { Vulnerability } from '../../types/scan.types';

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

  // Fetch report data
  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        // Fetch the scan results from the backend
        const response = await api.scan.getResults(scanId || '');
        console.log('Scan results:', response.data);
        
        // Transform the scan data into report format
        const scanData = response.data;
        
        // Count vulnerabilities by severity
        const criticalCount = scanData.findings?.filter((f: Vulnerability) => f.severity >= 9.0).length || 0;
        const highCount = scanData.findings?.filter((f: Vulnerability) => f.severity >= 7.0 && f.severity < 9.0).length || 0;
        const mediumCount = scanData.findings?.filter((f: Vulnerability) => f.severity >= 4.0 && f.severity < 7.0).length || 0;
        const lowCount = scanData.findings?.filter((f: Vulnerability) => f.severity < 4.0).length || 0;
        
        const reportData: ReportData = {
          metadata: {
            report_id: `report-${scanId}`,
            scan_id: scanId || '',
            target: scanData.target,
            generated_at: scanData.end_time || new Date().toISOString(),
            tools_used: scanData.tools_executed || [],
            duration_seconds: scanData.time_elapsed || 0,
            coverage_percentage: scanData.coverage || 0
          },
          executive_summary: {
            risk_level: criticalCount > 0 ? 'Critical' : highCount > 0 ? 'High' : mediumCount > 0 ? 'Medium' : 'Low',
            total_findings: scanData.findings?.length || 0,
            critical_vulnerabilities: criticalCount,
            high_vulnerabilities: highCount,
            medium_vulnerabilities: mediumCount,
            low_vulnerabilities: lowCount,
            summary_text: `Security scan of ${scanData.target} identified ${scanData.findings?.length || 0} vulnerabilities, including ${criticalCount} critical and ${highCount} high severity issues.`
          },
          vulnerabilities: scanData.findings || [],
          attack_chain: [],
          recommendations: []
        };
        
        setReportData(reportData);
      } catch (err: any) {
        setError('Failed to load report data: ' + (err.response?.data?.error || err.message));
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

  const getSeverityColor = (severity: number) => {
    if (severity >= 9.0) return 'bg-red-500 text-white';
    if (severity >= 7.0) return 'bg-orange-500 text-white';
    if (severity >= 4.0) return 'bg-yellow-500 text-black';
    return 'bg-green-500 text-white';
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
              {reportData.vulnerabilities.map((vuln, index) => (
                <tr 
                  key={index} 
                  className="border-b hover:bg-gray-50 cursor-pointer"
                  onClick={() => setSelectedVulnerability(vuln)}
                >
                  <td className="py-2 px-4">{vuln.name}</td>
                  <td className="py-2 px-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity.toFixed(1)}
                    </span>
                  </td>
                  <td className="py-2 px-4">{vuln.severity.toFixed(1)}</td>
                  <td className="py-2 px-4">{vuln.location || 'N/A'}</td>
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
                <h3 className="text-2xl font-bold">{selectedVulnerability.name}</h3>
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
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getSeverityColor(selectedVulnerability.severity)}`}>
                  Severity: {selectedVulnerability.severity.toFixed(1)}
                </span>
              </div>
              
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-2">Description</h4>
                <p className="text-gray-700">{selectedVulnerability.name}</p>
              </div>
              
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-2">Technical Details</h4>
                <div className="bg-gray-100 p-4 rounded">
                  <p><strong>Location:</strong> {selectedVulnerability.location || 'N/A'}</p>
                  <p><strong>Tool:</strong> {selectedVulnerability.tool || 'N/A'}</p>
                  <p><strong>Evidence:</strong> <code className="bg-gray-200 px-1 rounded">{selectedVulnerability.evidence || 'N/A'}</code></p>
                </div>
              </div>
              
              <div className="mb-6">
                <h4 className="text-lg font-semibold mb-2">Remediation</h4>
                <p className="text-gray-700">{selectedVulnerability.remediation || 'No specific remediation provided'}</p>
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