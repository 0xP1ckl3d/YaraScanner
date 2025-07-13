import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL;

function App() {
  const [files, setFiles] = useState([]);
  const [textContent, setTextContent] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [rulesInfo, setRulesInfo] = useState(null);
  const [activeTab, setActiveTab] = useState('files');
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    fetchRulesInfo();
  }, []);

  const fetchRulesInfo = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/rules/latest`);
      setRulesInfo(response.data);
    } catch (error) {
      console.error('Error fetching rules info:', error);
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
        return `${baseClasses} bg-green-100 text-green-800`;
      case 'suspicious':
        return `${baseClasses} bg-yellow-100 text-yellow-800`;
      case 'bad':
        return `${baseClasses} bg-red-100 text-red-800`;
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
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-purple-600 rounded-2xl mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-4xl font-bold text-white mb-2">EDR-Safe Scanner</h1>
          <p className="text-purple-200 text-lg">Local YARA/Sigma rule scanner for secure file analysis</p>
        </div>

        {/* Rules Info */}
        {rulesInfo && (
          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 mb-8 border border-white/20">
            <h2 className="text-xl font-semibold text-white mb-4">📊 Rules Database Status</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-white/5 rounded-lg p-4">
                <div className="text-purple-300 text-sm">Last Built</div>
                <div className="text-white font-medium">
                  {new Date(rulesInfo.built).toLocaleDateString()}
                </div>
              </div>
              <div className="bg-white/5 rounded-lg p-4">
                <div className="text-purple-300 text-sm">Rule Sources</div>
                <div className="text-white font-medium">{rulesInfo.sources.length} sources</div>
              </div>
              <div className="bg-white/5 rounded-lg p-4">
                <div className="text-purple-300 text-sm">Total Rules</div>
                <div className="text-white font-medium">{rulesInfo.total_rules || 'N/A'}</div>
              </div>
            </div>
          </div>
        )}

        {/* Main Content */}
        <div className="bg-white/10 backdrop-blur-md rounded-xl border border-white/20 overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-white/20">
            <button
              className={`flex-1 px-6 py-4 font-medium transition-colors ${
                activeTab === 'files'
                  ? 'bg-purple-600 text-white'
                  : 'text-purple-200 hover:text-white hover:bg-white/5'
              }`}
              onClick={() => setActiveTab('files')}
            >
              📁 File Upload
            </button>
            <button
              className={`flex-1 px-6 py-4 font-medium transition-colors ${
                activeTab === 'text'
                  ? 'bg-purple-600 text-white'
                  : 'text-purple-200 hover:text-white hover:bg-white/5'
              }`}
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
                      ? 'border-purple-400 bg-purple-600/20'
                      : 'border-white/30 hover:border-purple-400 hover:bg-white/5'
                  }`}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                >
                  <div className="mb-4">
                    <svg className="mx-auto h-12 w-12 text-purple-300" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                      <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                  <div className="text-white mb-2">
                    <label htmlFor="file-upload" className="cursor-pointer">
                      <span className="text-purple-300 font-medium hover:text-purple-200">
                        Click to upload
                      </span>
                      <span className="text-purple-200"> or drag and drop</span>
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
                  <p className="text-purple-300 text-sm">Maximum 20MB total</p>
                </div>

                {/* Selected Files */}
                {files.length > 0 && (
                  <div className="mt-6">
                    <div className="flex justify-between items-center mb-4">
                      <h3 className="text-white font-medium">Selected Files ({files.length})</h3>
                      <div className="text-purple-300 text-sm">
                        Total: {formatFileSize(getTotalSize())}
                      </div>
                    </div>
                    <div className="space-y-2 max-h-40 overflow-y-auto">
                      {files.map((file, index) => (
                        <div key={index} className="flex items-center justify-between bg-white/5 rounded-lg p-3">
                          <div className="flex-1 min-w-0">
                            <div className="text-white font-medium truncate">{file.name}</div>
                            <div className="text-purple-300 text-sm">{formatFileSize(file.size)}</div>
                          </div>
                          <button
                            onClick={() => removeFile(index)}
                            className="ml-4 text-red-400 hover:text-red-300 transition-colors"
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
                  className="w-full mt-6 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium py-3 px-6 rounded-lg transition-colors"
                >
                  {isScanning ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Scanning...
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
                  <label className="block text-white font-medium mb-3">Enter text content to analyze:</label>
                  <textarea
                    value={textContent}
                    onChange={(e) => setTextContent(e.target.value)}
                    className="w-full h-40 bg-white/5 border border-white/20 rounded-lg px-4 py-3 text-white placeholder-purple-300 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent resize-none"
                    placeholder="Paste suspicious text, code, or content here..."
                  />
                </div>

                <button
                  onClick={scanText}
                  disabled={!textContent.trim() || isScanning}
                  className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium py-3 px-6 rounded-lg transition-colors"
                >
                  {isScanning ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Scanning...
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
          <div className="mt-8 bg-white/10 backdrop-blur-md rounded-xl border border-white/20 overflow-hidden">
            <div className="px-6 py-4 border-b border-white/20">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-semibold text-white">Scan Results</h2>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(scanResults, null, 2))}
                  className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg text-sm transition-colors"
                >
                  📋 Copy JSON
                </button>
              </div>
              <div className="text-purple-300 text-sm mt-1">
                Scan ID: {scanResults.scan_id} • {scanResults.total_files} file(s) processed
              </div>
            </div>
            
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5">
                  <tr>
                    <th className="text-left px-6 py-3 text-purple-300 font-medium">Filename</th>
                    <th className="text-left px-6 py-3 text-purple-300 font-medium">Status</th>
                    <th className="text-left px-6 py-3 text-purple-300 font-medium">Matches</th>
                    <th className="text-left px-6 py-3 text-purple-300 font-medium">Scan Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {scanResults.results.map((result, index) => (
                    <tr key={index} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4 text-white font-medium">{result.filename}</td>
                      <td className="px-6 py-4">
                        <span className={getStatusBadge(result.status)}>
                          {result.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {result.matches.length > 0 ? (
                          <div className="space-y-1">
                            {result.matches.map((match, matchIndex) => (
                              <div key={matchIndex} className="text-purple-200 text-sm bg-white/5 rounded px-2 py-1 inline-block mr-1 mb-1">
                                {match}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-gray-400">No matches</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-purple-300 text-sm">
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
        <div className="mt-12 text-center text-purple-300">
          <p className="text-sm">
            🔒 All scanning is performed locally. No data leaves your environment.
          </p>
        </div>
      </div>
    </div>
  );
}

export default App;