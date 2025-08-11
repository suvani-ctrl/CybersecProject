import React, { useState } from "react";
import axios from "axios";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
} from "recharts";
import { motion } from "framer-motion";
import { Loader2, FileText, Shield, AlertTriangle, CheckCircle, Clock, FileIcon, Target, Zap } from "lucide-react";
import "./App.css";
import jsPDF from "jspdf";
import html2canvas from "html2canvas";

// Complementary color palette - professional and easy on the eyes
const PIE_COLORS = [
  "#00b894", // Teal green
  "#f39c12", // Orange
  "#3498db", // Blue
  "#e74c3c", // Red
  "#9b59b6", // Purple
  "#f1c40f", // Yellow
  "#1abc9c", // Turquoise
  "#e67e22", // Dark orange
  "#34495e"  // Dark blue-gray
];

const COLORS = PIE_COLORS;
const NEON_COLORS = PIE_COLORS;

// Malware family mapping
const MALWARE_FAMILIES = {
  "report_backdoor": { emoji: "🔓", name: "Backdoor", danger: "HIGH" },
  "report_clean": { emoji: "✅", name: "Clean", danger: "SAFE" },
  "report_coinminer": { emoji: "⛏️", name: "Coinminer", danger: "MEDIUM" },
  "report_dropper": { emoji: "📦", name: "Dropper", danger: "HIGH" },
  "report_keylogger": { emoji: "⌨️", name: "Keylogger", danger: "HIGH" },
  "report_ransomware": { emoji: "🔐", name: "Ransomware", danger: "CRITICAL" },
  "report_rat": { emoji: "🕷️", name: "RAT", danger: "HIGH" },
  "report_trojan": { emoji: "🐴", name: "Trojan", danger: "HIGH" },
  "report_windows_syswow64": { emoji: "🖥️", name: "Windows System", danger: "SAFE" },
};

// Numeric to family mapping for fallback
const NUMERIC_FAMILIES = {
  0: { emoji: "🔓", name: "Backdoor", danger: "HIGH" },
  1: { emoji: "✅", name: "Clean", danger: "SAFE" },
  2: { emoji: "⛏️", name: "Coinminer", danger: "MEDIUM" },
  3: { emoji: "📦", name: "Dropper", danger: "HIGH" },
  4: { emoji: "⌨️", name: "Keylogger", danger: "HIGH" },
  5: { emoji: "🔐", name: "Ransomware", danger: "CRITICAL" },
  6: { emoji: "🕷️", name: "RAT", danger: "HIGH" },
  7: { emoji: "🐴", name: "Trojan", danger: "HIGH" },
  8: { emoji: "🖥️", name: "Windows System", danger: "SAFE" },
};

export default function MalwareApp() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const reset = () => {
    setResult(null);
    setError("");
  };

  const onFileChange = (e) => {
    reset();
    setFile(e.target.files[0]);
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError("Please select a file to upload.");
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const { data } = await axios.post("http://localhost:5000/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      const fixedStatus =
        data.prediction?.toLowerCase() === "clean" ? "Clean" : "Malicious";
      setResult({ ...data, status: fixedStatus });
    } catch (err) {
      setError(err.response?.data?.error || "Upload failed, try again.");
    } finally {
      setLoading(false);
    }
  };

  const getFamilyInfo = (familyName) => {
    // Try to get family info from various sources
    if (MALWARE_FAMILIES[familyName]) {
      return MALWARE_FAMILIES[familyName];
    }
    
    // Check if it's a numeric value
    const numericValue = parseInt(familyName);
    if (!isNaN(numericValue) && NUMERIC_FAMILIES[numericValue]) {
      return NUMERIC_FAMILIES[numericValue];
    }
    
    // Fallback
    return { emoji: "❓", name: "Unknown", danger: "UNKNOWN" };
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 80) return "#00ff88"; // Green
    if (confidence >= 50) return "#ff6b35"; // Orange
    return "#ff4757"; // Red
  };

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case "clean":
        return "#00ff88";
      case "malicious":
        return "#ff4757";
      default:
        return "#ffa502";
    }
  };

  const formatChartData = (families, probabilities) => {
    if (!families || !probabilities) return [];
    
    return families.map((family, index) => {
      const familyInfo = getFamilyInfo(family);
      return {
        family: familyInfo.emoji,
        name: familyInfo.name,
        confidence: probabilities[index] || 0,
        color: getConfidenceColor(probabilities[index] || 0),
      };
    });
  };

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="custom-tooltip">
          <p className="tooltip-label">{`${label} (${payload[0].payload.name})`}</p>
          <p className="tooltip-value">{`Confidence: ${payload[0].value.toFixed(2)}%`}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="malware-dashboard">
      <motion.div
        initial={{ opacity: 0, y: -30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7 }}
        className="dashboard-container"
      >
        {/* Header with Glitch Effect */}
        <header className="dashboard-header">
          <h1 className="glitch-title" data-text="MALWARE DETECTION SYSTEM">
            MALWARE DETECTION SYSTEM
          </h1>
          <p className="dashboard-subtitle">Advanced Threat Analysis & Intelligence Platform</p>
        </header>

        {/* Upload Section */}
        <section className="upload-section">
          <form onSubmit={onSubmit} className="upload-form">
            <div className="file-upload-area">
              <FileIcon className="upload-icon" />
              <input
                type="file"
                onChange={onFileChange}
                disabled={loading}
                className="file-input"
                accept="*/*"
              />
              <label htmlFor="file-input" className="upload-label">
                {file ? file.name : "Select File for Analysis"}
              </label>
            </div>
            <button type="submit" disabled={loading} className="analyze-btn">
              {loading ? (
                <>
                  <Loader2 className="loader" size={20} />
                  Analyzing...
                </>
              ) : (
                <>
                  <Zap className="analyze-icon" size={20} />
                  Analyze Threat
                </>
              )}
            </button>
          </form>
        </section>

        {error && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="error-alert"
          >
            <AlertTriangle className="error-icon" />
            <span>{error}</span>
          </motion.div>
        )}

        {result && (
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7 }}
            className="results-section"
            id="result-section"
          >
            {/* Main Results Header */}
            <div className="results-header">
              <div className="result-main-info">
                <div className="file-info-display">
                  <FileText className="file-icon" />
                  <span className="filename">{result.filename || "Unknown"}</span>
                </div>
                <div className="timestamp-display">
                  <Clock className="clock-icon" />
                  <span>{result.timestamp ? new Date(result.timestamp).toLocaleString() : "N/A"}</span>
                </div>
              </div>
              
              <div className="prediction-display">
                <div className="prediction-main">
                  <span className="prediction-emoji">
                    {getFamilyInfo(result.prediction).emoji}
                  </span>
                  <div className="prediction-details">
                    <h2 className="prediction-family">{getFamilyInfo(result.prediction).name}</h2>
                    <span className="prediction-danger">{getFamilyInfo(result.prediction).danger}</span>
                  </div>
                </div>
                <div className="confidence-display">
                  <Target className="target-icon" />
                  <span className="confidence-value">{result.confidence ? `${result.confidence.toFixed(1)}%` : "N/A"}</span>
                </div>
              </div>
            </div>

            {/* Cute Pie Chart - Emoji Only */}
            {result.families && result.probabilities && (
              <div className="chart-section">
                <h3 className="section-title">Threat Distribution Pie Chart</h3>
                <ResponsiveContainer width="100%" height={350}>
                  <PieChart>
                    <Pie
                      data={formatChartData(result.families, result.probabilities)}
                      dataKey="confidence"
                      nameKey="family"
                      cx="50%"
                      cy="50%"
                      outerRadius={120}
                      innerRadius={60}
                      label={({ family, confidence }) => `${family} ${confidence.toFixed(1)}%`}
                      labelLine={false}
                      className="pie-chart"
                    >
                      {formatChartData(result.families, result.probabilities).map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={PIE_COLORS[index % PIE_COLORS.length]}
                          stroke="#1a1a1a"
                          strokeWidth={2}
                        />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* All Malware Families Analysis - Emoji Only */}
            {result.families && result.probabilities && (
              <div className="chart-section">
                <h3 className="section-title">All Malware Families Analysis</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart
                    data={formatChartData(result.families, result.probabilities)}
                    margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis 
                      dataKey="family" 
                      stroke="#00b894" 
                      fontSize={24}
                      tick={{ fill: '#00b894' }}
                    />
                    <YAxis 
                      stroke="#00b894" 
                      tick={{ fill: '#00b894' }}
                      label={{ value: 'Confidence %', angle: -90, position: 'insideLeft', fill: '#00b894' }}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar 
                      dataKey="confidence" 
                      radius={[4, 4, 0, 0]}
                      className="confidence-bar"
                    >
                      {formatChartData(result.families, result.probabilities).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Confidence Distribution Trend - Emoji Only */}
            {result.families && result.probabilities && (
              <div className="chart-section">
                <h3 className="section-title">Confidence Distribution Trend</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart
                    data={formatChartData(result.families, result.probabilities)}
                    margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis 
                      dataKey="family" 
                      stroke="#00ff88" 
                      fontSize={24}
                      tick={{ fill: '#00ff88' }}
                    />
                    <YAxis 
                      stroke="#00ff88" 
                      tick={{ fill: '#00ff88' }}
                      label={{ value: 'Confidence %', angle: -90, position: 'insideLeft', fill: '#00ff88' }}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Line 
                      type="monotone" 
                      dataKey="confidence" 
                      stroke="#00ff88" 
                      strokeWidth={3}
                      dot={{ fill: '#00ff88', strokeWidth: 2, r: 6 }}
                      activeDot={{ r: 8, stroke: '#00ff88', strokeWidth: 2 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Malware Family Legend */}
            <div className="legend-section">
              <h3 className="section-title">Threat Intelligence Legend</h3>
              <div className="family-legend">
                {Object.entries(MALWARE_FAMILIES).map(([key, family], index) => (
                  <motion.div
                    key={key}
                    className="legend-item"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    whileHover={{ scale: 1.05, y: -2 }}
                  >
                    <span className="legend-emoji">{family.emoji}</span>
                    <div className="legend-content">
                      <span className="legend-name">{family.name}</span>
                      <span className="legend-index">({Object.keys(MALWARE_FAMILIES).indexOf(key)})</span>
                    </div>
                    <span className={`legend-danger danger-${family.danger.toLowerCase()}`}>
                      {family.danger}
                    </span>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Download Report */}
            <div className="action-section">
              <button
                onClick={async () => {
                  const input = document.getElementById("result-section");
                  if (!input) return;
                  const canvas = await html2canvas(input, { scale: 2 });
                  const imgData = canvas.toDataURL("image/png");
                  const pdf = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
                  const pageWidth = pdf.internal.pageSize.getWidth();
                  const pageHeight = pdf.internal.pageSize.getHeight();
                  const imgWidth = pageWidth - 40;
                  const imgHeight = (canvas.height * imgWidth) / canvas.width;
                  pdf.addImage(imgData, "PNG", 20, 20, imgWidth, imgHeight);
                  pdf.save(`${result.filename || "malware_report"}.pdf`);
                }}
                className="download-btn"
              >
                <FileText className="download-icon" />
                Download Threat Report
              </button>
            </div>
          </motion.section>
        )}
      </motion.div>
    </div>
  );
}
