import React, { useState } from 'react';
import axios from 'axios';
import "../uploadForm.css"
const UploadForm = ({ onResult }) => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a .json file.');
      return;
    }
    if (!file.name.endsWith('.json')) {
      setError('Only .json files are allowed.');
      return;
    }
    setLoading(true);
    setError('');
    const formData = new FormData();
    formData.append('file', file);
    try {
      const response = await axios.post('http://localhost:5000/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      onResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Upload failed.');
      onResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="upload-form">
      <input
        type="file"
        accept=".json"
        onChange={handleFileChange}
        className="file-input"
        disabled={loading}
      />
      <button type="submit" className="submit-btn" disabled={loading}>
        {loading ? 'Analyzing...' : 'Upload & Analyze'}
      </button>
      {error && <div className="error-msg">{error}</div>}
    </form>
  );
};

export default UploadForm;
