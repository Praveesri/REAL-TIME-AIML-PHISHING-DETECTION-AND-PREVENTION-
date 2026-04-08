import { useState } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const checkUrl = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      // Clean up URL if it lacks scheme
      let targetUrl = url.trim();
      
      const response = await fetch('http://localhost:8000/api/check-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: targetUrl }),
      });

      if (!response.ok) {
        throw new Error('Server error: Please check if backend is running.');
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      setError(err.message || 'Error connecting to the analysis server.');
    } finally {
      setLoading(false);
    }
  };

  const isPhishing = result?.result === 'Phishing';
  const score = result ? (result.phishing_probability * 100).toFixed(0) : 0;

  // Format Feature name nicely 
  const formatFeatureName = (str) => {
    return str.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  };

  // Determine if a feature value is risky (this is a heuristic for UI colors)
  const isFeatureRisky = (key, val) => {
    if (key === 'url_length' && val > 54) return true;
    if (key === 'has_at_symbol' && val === 1) return true;
    if (key === 'has_ip_address' && val === 1) return true;
    if (key === 'num_hyphens' && val > 2) return true;
    if (key === 'has_suspicious_words' && val === 1) return true;
    if (key === 'is_https' && val === 0) return true;
    if (key === 'has_hidden_elements' && val === 1) return true;
    return false;
  };

  const getFeatureClass = (key, val) => {
    if (key === 'url_length') return val > 54 ? 'bad' : 'good';
    if (key === 'num_hyphens' || key === 'num_subdomains') return val > 2 ? 'bad' : 'neutral';
    
    // For binary features
    if (val === 1 || val === 0) {
      return isFeatureRisky(key, val) ? 'bad' : 'good';
    }
    return 'neutral';
  };

  return (
    <div className="app-container">
      <div className="glass-panel">
        <h1 className="title">AI Phishing Shield</h1>
        <p className="subtitle">
          Real-time Machine Learning detection system. Enter any URL to analyze it against our trained predictive models and active feature extraction.
        </p>

        <form className="search-form" onSubmit={checkUrl}>
          <input
            type="text"
            className="search-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="e.g. https://secure-login.paypal-update.com"
            disabled={loading}
          />
          <button type="submit" className="search-btn" disabled={loading || !url.trim()}>
            {loading ? 'Scanning...' : 'Analyze'}
          </button>
        </form>

        {error && <div className="error-message">{error}</div>}

        {loading && (
          <div className="loader">
            <span></span>
            <span></span>
            <span></span>
          </div>
        )}

        {result && (
          <div className="result-container">
            <div className={`result-card ${isPhishing ? 'phishing' : 'safe'}`}>
              <div className="result-icon">
                {isPhishing ? (
                  <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                  </svg>
                ) : (
                  <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                  </svg>
                )}
              </div>
              <h2 className={`result-score ${isPhishing ? 'phishing-text' : 'safe-text'}`}>
                {isPhishing ? 'Phishing Detected!' : 'Website is Safe'}
              </h2>
              <p className="result-desc">
                Our model is <strong>{isPhishing ? score : (100 - score)}%</strong> confident about this result.
              </p>
            </div>

            <h3 style={{ marginTop: '40px', color: '#f8fafc', fontWeight: 600 }}>Extracted Web Features</h3>
            <div className="features-grid">
              {Object.entries(result.features).map(([key, val]) => (
                <div className="feature-item" key={key}>
                  <span className="feature-label">{formatFeatureName(key)}</span>
                  <span className={`feature-val ${getFeatureClass(key, val)}`}>
                    {val === 1 && key.startsWith('has') || key.startsWith('is') ? 'Yes' : 
                     val === 0 && key.startsWith('has') || key.startsWith('is') ? 'No' : val}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
