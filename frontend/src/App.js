import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL;

// Infotrust brand colors
const brandColors = {
  brandGreen: '#37B34A',
  brandDark: '#142237',
  brandLight: '#F5F7FA', 
  accentLime: '#A9E044',
  accentTeal: '#1FBED6',
  statusClean: '#9BA3AF',
  statusSuspicious: '#1FBED6',
  statusBad: '#D0312D'
};

function App() {
  const [files, setFiles] = useState([]);
  const [textContent, setTextContent] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [rulesStats, setRulesStats] = useState(null);
  const [activeTab, setActiveTab] = useState('files');
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    fetchRulesStats();
    const interval = setInterval(fetchRulesStats, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchRulesStats = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/rules/stats`);
      setRulesStats(response.data);
    } catch (error) {
      console.error('Error fetching rules stats:', error);
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFiles = Array.from(e.dataTransfer.files);
      setFiles(prev => [...prev, ...droppedFiles]);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files);
      setFiles(prev => [...prev, ...selectedFiles]);
    }
  };

  const removeFile = (index) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const getTotalSize = () => {
    return files.reduce((total, file) => total + file.size, 0);
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const scanFiles = async () => {
    if (files.length === 0) {
      alert('Please select files to scan');
      return;
    }

    const totalSize = getTotalSize();
    if (totalSize > 20 * 1024 * 1024) {
      alert('Total file size exceeds 20MB limit');
      return;
    }

    setIsScanning(true);
    setScanResults(null);

    try {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      const response = await axios.post(`${API_BASE_URL}/api/scan`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setScanResults(response.data);
    } catch (error) {
      console.error('Error scanning files:', error);
      alert('Error scanning files: ' + (error.response?.data?.detail || error.message));
    } finally {
      setIsScanning(false);
    }
  };

  const scanText = async () => {
    if (!textContent.trim()) {
      alert('Please enter text content to scan');
      return;
    }

    setIsScanning(true);
    setScanResults(null);

    try {
      const formData = new FormData();
      formData.append('content', textContent);
      formData.append('filename', 'text_input.txt');

      const response = await axios.post(`${API_BASE_URL}/api/scan/text`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setScanResults(response.data);
    } catch (error) {
      console.error('Error scanning text:', error);
      alert('Error scanning text: ' + (error.response?.data?.detail || error.message));
    } finally {
      setIsScanning(false);
    }
  };

  const getStatusBadge = (status) => {
    const baseClasses = 'px-3 py-1 rounded-full text-sm font-medium';
    switch (status) {
      case 'clean':
        return `${baseClasses} text-white` + ` bg-[${brandColors.statusClean}]`;
      case 'suspicious':
        return `${baseClasses} text-white` + ` bg-[${brandColors.statusSuspicious}]`;
      case 'bad':
        return `${baseClasses} text-white` + ` bg-[${brandColors.statusBad}]`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      alert('Copied to clipboard!');
    });
  };

  return (
    <div className="min-h-screen" style={{ backgroundColor: brandColors.brandLight }}>
      {/* Header with Infotrust branding */}
      <header className="shadow-lg" style={{ backgroundColor: brandColors.brandDark }}>
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 rounded-lg flex items-center justify-center" style={{ backgroundColor: brandColors.brandGreen }}>
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">EDR-Safe Scanner</h1>
                <p className="text-gray-300 text-sm">Local YARA/Sigma rule scanner</p>
              </div>
            </div>
            
            {/* Memory/RSS widget */}
            {rulesStats && (
              <div className="text-right">
                <div className="text-sm" style={{ color: brandColors.accentLime }}>
                  RSS Memory: {rulesStats.rss_mb.toFixed(1)} MB
                </div>
                <div className="text-xs text-gray-300">
                  {rulesStats.total_rules} rules loaded
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        {/* Rules Statistics Dashboard */}
        {rulesStats && (
          <div className="bg-white rounded-xl shadow-lg p-6 mb-8 border-l-4" style={{ borderLeftColor: brandColors.brandGreen }}>
            <h2 className="text-xl font-semibold mb-4" style={{ color: brandColors.brandDark }}>
              📊 Security Rules Status
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-lg" style={{ backgroundColor: brandColors.brandLight }}>
                <div className="text-sm text-gray-600">Generic Rules</div>
                <div className="text-2xl font-bold" style={{ color: brandColors.brandDark }}>
                  {rulesStats.bundle_counts.generic || 0}
                </div>
              </div>
              <div className="p-4 rounded-lg" style={{ backgroundColor: brandColors.brandLight }}>
                <div className="text-sm text-gray-600">Script Analysis</div>
                <div className="text-2xl font-bold" style={{ color: brandColors.brandDark }}>
                  {rulesStats.bundle_counts.scripts || 0}
                </div>
              </div>
              <div className="p-4 rounded-lg" style={{ backgroundColor: brandColors.brandLight }}>
                <div className="text-sm text-gray-600">PE Detection</div>
                <div className="text-2xl font-bold" style={{ color: brandColors.brandDark }}>
                  {rulesStats.bundle_counts.pe || 0}
                </div>
              </div>
              <div className="p-4 rounded-lg" style={{ backgroundColor: brandColors.brandLight }}>
                <div className="text-sm text-gray-600">Webshell Detection</div>
                <div className="text-2xl font-bold" style={{ color: brandColors.brandDark }}>
                  {rulesStats.bundle_counts.webshells || 0}
                </div>
              </div>
            </div>
            <div className="mt-4 text-sm text-gray-600">
              Last updated: {new Date(rulesStats.built).toLocaleString()}
              {rulesStats.local_count && (
                <span className="ml-4 px-2 py-1 rounded text-xs" style={{ backgroundColor: brandColors.accentLime, color: 'white' }}>
                  +{rulesStats.local_count} local rules
                </span>
              )}
            </div>
          </div>
        )}

        {/* Main Scanning Interface */}
        <div className="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-gray-200">
            <button
              className={`flex-1 px-6 py-4 font-medium transition-colors ${
                activeTab === 'files'
                  ? 'text-white'
                  : 'text-gray-600 hover:text-white hover:bg-gray-600'
              }`}
              style={{ backgroundColor: activeTab === 'files' ? brandColors.brandGreen : 'transparent' }}
              onClick={() => setActiveTab('files')}
            >
              📁 File Upload
            </button>
            <button
              className={`flex-1 px-6 py-4 font-medium transition-colors ${
                activeTab === 'text'
                  ? 'text-white'
                  : 'text-gray-600 hover:text-white hover:bg-gray-600'
              }`}
              style={{ backgroundColor: activeTab === 'text' ? brandColors.brandGreen : 'transparent' }}
              onClick={() => setActiveTab('text')}
            >
              📝 Text Analysis
            </button>
          </div>

          <div className="p-8">
            {activeTab === 'files' ? (
              <div>
                {/* File Upload Area */}
                <div
                  className={`border-2 border-dashed rounded-xl p-8 text-center transition-all ${
                    dragActive
                      ? 'border-opacity-100 bg-opacity-20'
                      : 'border-gray-300 hover:border-opacity-100 hover:bg-gray-50'
                  }`}
                  style={{ 
                    borderColor: dragActive ? brandColors.brandGreen : undefined,
                    backgroundColor: dragActive ? brandColors.brandLight : undefined
                  }}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                >
                  <div className="mb-4">
                    <svg className="mx-auto h-12 w-12" style={{ color: brandColors.brandGreen }} stroke="currentColor" fill="none" viewBox="0 0 48 48">
                      <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                  <div className="mb-2" style={{ color: brandColors.brandDark }}>
                    <label htmlFor="file-upload" className="cursor-pointer">
                      <span className="font-medium hover:underline" style={{ color: brandColors.brandGreen }}>
                        Click to upload
                      </span>
                      <span className="text-gray-600"> or drag and drop</span>
                    </label>
                    <input
                      id="file-upload"
                      name="file-upload"
                      type="file"
                      className="sr-only"
                      multiple
                      onChange={handleFileSelect}
                    />
                  </div>
                  <p className="text-gray-500 text-sm">Maximum 20MB total • Supports archives</p>
                </div>

                {/* Selected Files */}
                {files.length > 0 && (
                  <div className="mt-6">
                    <div className="flex justify-between items-center mb-4">
                      <h3 className="font-medium" style={{ color: brandColors.brandDark }}>
                        Selected Files ({files.length})
                      </h3>
                      <div className="text-sm text-gray-600">
                        Total: {formatFileSize(getTotalSize())}
                      </div>
                    </div>
                    <div className="space-y-2 max-h-40 overflow-y-auto">
                      {files.map((file, index) => (
                        <div key={index} className="flex items-center justify-between bg-gray-50 rounded-lg p-3">
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-gray-900 truncate">{file.name}</div>
                            <div className="text-gray-500 text-sm">{formatFileSize(file.size)}</div>
                          </div>
                          <button
                            onClick={() => removeFile(index)}
                            className="ml-4 text-red-500 hover:text-red-700 transition-colors"
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <button
                  onClick={scanFiles}
                  disabled={files.length === 0 || isScanning}
                  className="w-full mt-6 text-white font-medium py-3 px-6 rounded-lg transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                  style={{ backgroundColor: files.length === 0 || isScanning ? undefined : brandColors.brandGreen }}
                >
                  {isScanning ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Analyzing...
                    </span>
                  ) : (
                    '🔍 Scan Files'
                  )}
                </button>
              </div>
            ) : (
              <div>
                {/* Text Input */}
                <div className="mb-6">
                  <label className="block font-medium mb-3" style={{ color: brandColors.brandDark }}>
                    Enter text content to analyze:
                  </label>
                  <textarea
                    value={textContent}
                    onChange={(e) => setTextContent(e.target.value)}
                    className="w-full h-40 border border-gray-300 rounded-lg px-4 py-3 text-gray-900 placeholder-gray-500 focus:outline-none focus:ring-2 focus:border-transparent resize-none"
                    style={{ focusRingColor: brandColors.brandGreen }}
                    placeholder="Paste suspicious text, code, or content here..."
                  />
                </div>

                <button
                  onClick={scanText}
                  disabled={!textContent.trim() || isScanning}
                  className="w-full text-white font-medium py-3 px-6 rounded-lg transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                  style={{ backgroundColor: !textContent.trim() || isScanning ? undefined : brandColors.brandGreen }}
                >
                  {isScanning ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Analyzing...
                    </span>
                  ) : (
                    '🔍 Scan Text'
                  )}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Results */}
        {scanResults && (
          <div className="mt-8 bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200" style={{ backgroundColor: brandColors.brandLight }}>
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-semibold" style={{ color: brandColors.brandDark }}>
                  Scan Results
                </h2>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(scanResults, null, 2))}
                  className="text-white px-4 py-2 rounded-lg text-sm transition-colors"
                  style={{ backgroundColor: brandColors.brandGreen }}
                >
                  📋 Copy JSON
                </button>
              </div>
              <div className="text-gray-600 text-sm mt-1">
                Scan ID: {scanResults.scan_id} • {scanResults.total_files} file(s) processed
              </div>
            </div>
            
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead style={{ backgroundColor: brandColors.brandLight }}>
                  <tr>
                    <th className="text-left px-6 py-3 text-gray-700 font-medium">Filename</th>
                    <th className="text-left px-6 py-3 text-gray-700 font-medium">Status</th>
                    <th className="text-left px-6 py-3 text-gray-700 font-medium">Bundle</th>
                    <th className="text-left px-6 py-3 text-gray-700 font-medium">Matches</th>
                    <th className="text-left px-6 py-3 text-gray-700 font-medium">Scan Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {scanResults.results.map((result, index) => (
                    <tr key={index} className="hover:bg-gray-50 transition-colors">
                      <td className="px-6 py-4 font-medium text-gray-900">{result.filename}</td>
                      <td className="px-6 py-4">
                        <span 
                          className="px-3 py-1 rounded-full text-sm font-medium text-white"
                          style={{ 
                            backgroundColor: result.status === 'clean' ? brandColors.statusClean :
                                           result.status === 'suspicious' ? brandColors.statusSuspicious :
                                           result.status === 'bad' ? brandColors.statusBad : '#6B7280'
                          }}
                        >
                          {result.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {result.bundle_used && (
                          <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: brandColors.accentLime, color: 'white' }}>
                            {result.bundle_used}
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        {result.matches.length > 0 ? (
                          <div className="space-y-1">
                            {result.matches.slice(0, 3).map((match, matchIndex) => (
                              <div key={matchIndex} className="text-gray-700 text-sm bg-gray-100 rounded px-2 py-1 inline-block mr-1 mb-1">
                                {match}
                              </div>
                            ))}
                            {result.matches.length > 3 && (
                              <div className="text-xs text-gray-500">
                                +{result.matches.length - 3} more
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-gray-400">No matches</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-gray-500 text-sm">
                        {new Date(result.scan_time).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="mt-12 text-center text-gray-600">
          <p className="text-sm">
            🔒 All scanning is performed locally. No data leaves your environment.
          </p>
        </div>
      </div>
    </div>
  );
}

export default App;