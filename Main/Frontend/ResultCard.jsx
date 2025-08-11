import React from 'react';
import './ResultCard.css';

const ResultCard = ({ result }) => {
  if (!result) return null;
  const { prediction, confidence, status } = result;
  const statusColor = status === 'malicious' ? '#e53935' : '#43a047';

  return (
    <div className="result-card">
      <h2 className="result-title">Malware Detection Result</h2>
      <div className="result-row">
        <span className="result-label">Family:</span>
        <span className="result-value">{prediction}</span>
      </div>
      <div className="result-row">
        <span className="result-label">Status:</span>
        <span className="result-value" style={{ color: statusColor, fontWeight: 600 }}>{status.charAt(0).toUpperCase() + status.slice(1)}</span>
      </div>
      <div className="result-row">
        <span className="result-label">Confidence:</span>
        <span className="result-value">{confidence}%</span>
      </div>
    </div>
  );
};

export default ResultCard;
