import React, { useState, useEffect } from 'react';

function Reports({ addLog }) {
  const [reports, setReports] = useState([]);
  const [reportType, setReportType] = useState('SECURITY_SUMMARY');
  const [repError, setRepError] = useState('');
  const [repSuccess, setRepSuccess] = useState('');

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/reports/list');
      const data = await res.json();
      setReports(data);
    } catch (err) {}
  };

  const handleGenerate = async (e) => {
    e.preventDefault();
    setRepError('');
    setRepSuccess('');

    try {
      const res = await fetch('http://localhost:8000/api/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report_type: reportType })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Generation failed');
      }

      setRepSuccess(`Report generated successfully: ${data.filename}`);
      addLog(`Security PDF report compiled: ${data.filename}`, 'success');
      fetchReports();
    } catch (err) {
      setRepError(err.message);
      addLog(`Failed to compile report: ${err.message}`, 'error');
    }
  };

  const handleDownload = (reportId, filename) => {
    addLog(`Initiating download for document stream: ${filename}`, 'info');
    window.open(`http://localhost:8000/api/reports/download/${reportId}`, '_blank');
  };

  return (
    <div className="reports-container">
      <h2 className="section-title">📄 Security Audit PDF reports</h2>
      <p className="section-description">
        Compile summary PDF reports detailing firewall settings, detected threats, file monitor hashes, and network activity.
      </p>

      {repError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{repError}</div>}
      {repSuccess && <div className="auth-success" style={{ marginBottom: '15px' }}>{repSuccess}</div>}

      <div className="vault-grid">
        {/* Left Column: Generate Form */}
        <div className="reports-panel-left">
          <div className="cyber-widget generate-report-card">
            <div className="widget-title">
              <span>COMPILE PDF TEMPLATE AUDIT</span>
            </div>
            <form onSubmit={handleGenerate} className="report-form">
              <div className="form-group">
                <label className="form-label">Audit Report Scope</label>
                <select
                  className="cyber-input select-input"
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value)}
                >
                  <option value="SECURITY_SUMMARY">Full E2E Security Summary</option>
                  <option value="FIREWALL_AUDIT">Firewall Rules Audit Log</option>
                  <option value="THREAT_INDEX">Threat Intelligence Incident Log</option>
                  <option value="INTEGRITY_LOG">File Integrity Baseline Check</option>
                </select>
              </div>

              <button type="submit" className="cyber-btn compile-btn">
                📄 COMPILE SECURITY REPORT
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Reports List */}
        <div className="reports-panel-right">
          <div className="cyber-widget generated-reports-card">
            <div className="widget-title">
              <span>GENERATED DOCUMENT ARCHIVES</span>
              <span>{reports.length} ARCHIVES LOADED</span>
            </div>

            <div className="reports-list-container">
              {reports.length === 0 ? (
                <div className="reports-empty-placeholder">
                  <p>No reports generated in this session. Choose a template scope to begin compiling.</p>
                </div>
              ) : (
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>FILENAME</th>
                      <th>CREATED TIME</th>
                      <th>REPORT TYPE</th>
                      <th>DOWNLOAD</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reports.map((rep) => (
                      <tr key={rep.id}>
                        <td>
                          <div className="file-cell">
                            <span className="file-icon">📄</span>
                            <span className="file-name">{rep.filename}</span>
                          </div>
                        </td>
                        <td>{new Date(rep.created_at).toLocaleString()}</td>
                        <td>
                          <span className="protocol-badge">{rep.report_type}</span>
                        </td>
                        <td>
                          <button
                            className="cyber-table-btn"
                            onClick={() => handleDownload(rep.id, rep.filename)}
                          >
                            DOWNLOAD
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Reports;
