import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, Legend,
  LineChart, Line, XAxis, YAxis, CartesianGrid, BarChart, Bar
} from 'recharts';
import './HistoryPage.css';

const COLORS = ['#2563eb', '#60a5fa', '#38bdf8', '#818cf8', '#f472b6', '#facc15', '#34d399', '#f87171'];

const HistoryPage = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('http://localhost:5000/history')
      .then(res => setHistory(res.data))
      .catch(() => setHistory([]))
      .finally(() => setLoading(false));
  }, []);

  // Pie chart data: family distribution
  const familyCounts = history.reduce((acc, row) => {
    acc[row.prediction] = (acc[row.prediction] || 0) + 1;
    return acc;
  }, {});
  const pieData = Object.entries(familyCounts).map(([name, value]) => ({ name, value }));

  // Line/bar chart data: confidence over time
  const chartData = history.map(row => ({
    name: row.filename,
    confidence: parseFloat(row.confidence),
    timestamp: row.timestamp,
    prediction: row.prediction
  }));

  return (
    <div className="history-page">
      <h2>Upload History</h2>
      {loading ? <div>Loading...</div> : (
        <>
          <div className="history-table-wrap">
            <table className="history-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Date</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {history.map((row, i) => (
                  <tr key={i}>
                    <td>{row.filename}</td>
                    <td>{row.timestamp.replace('T', ' ')}</td>
                    <td>{row.prediction}</td>
                    <td>{row.confidence}%</td>
                    <td style={{ color: row.status === 'malicious' ? '#e53935' : '#43a047', fontWeight: 600 }}>{row.status.charAt(0).toUpperCase() + row.status.slice(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="charts-row">
            <div className="chart-card">
              <h3>Malware Family Distribution</h3>
              <PieChart width={280} height={220}>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label>
                  {pieData.map((entry, idx) => <Cell key={`cell-${idx}`} fill={COLORS[idx % COLORS.length]} />)}
                </Pie>
                <ReTooltip />
                <Legend />
              </PieChart>
            </div>
            <div className="chart-card">
              <h3>Model Confidence Over Time</h3>
              <BarChart width={320} height={220} data={chartData} margin={{ top: 20, right: 10, left: 0, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="timestamp" tick={{ fontSize: 10 }} angle={-30} textAnchor="end" height={60} />
                <YAxis domain={[0, 100]} />
                <ReTooltip />
                <Legend />
                <Bar dataKey="confidence" fill="#2563eb" name="Confidence (%)" />
              </BarChart>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default HistoryPage;
