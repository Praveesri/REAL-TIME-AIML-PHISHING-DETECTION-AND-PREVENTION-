import { useState } from 'react';
import './App.css';
import { extractFeatures } from './featureExtraction';
import { classifyUrl } from './phishingModel';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const checkUrl = (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setResult(null);
    setError(null);

    // Simulate a slight processing delay so the loader animation is visible
    setTimeout(() => {
      try {
        const rawUrl = url.trim();
        const features = extractFeatures(rawUrl);

        if (!features) {
          setError('Invalid URL. Please enter a valid web address.');
          setLoading(false);
          return;
        }

        const { result: verdict, phishing_probability } = classifyUrl(features);

        setResult({
          url: rawUrl,
          result: verdict,
          phishing_probability,
          features,
        });
      } catch (err) {
        setError('Analysis failed: ' + err.message);
      } finally {
        setLoading(false);
      }
    }, 800);
  };

  const isPhishing = result?.result === 'Phishing';
  const score = result ? (result.phishing_probability * 100).toFixed(0) : 0;

  // Format feature name nicely
  const formatFeatureName = (str) =>
    str.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');

  // Determine risk class for each feature
  const isFeatureRisky = (key, val) => {
    if (key === 'url_length' && val > 54) return true;
    if (key === 'is_long_url' && val === 1) return true;
    if (key === 'has_at_symbol' && val === 1) return true;
    if (key === 'has_ip_address' && val === 1) return true;
    if (key === 'num_hyphens' && val > 2) return true;
    if (key === 'has_hyphen_in_domain' && val === 1) return true;
    if (key === 'num_subdomains' && val > 1) return true;
    if (key === 'has_suspicious_words' && val === 1) return true;
    if (key === 'has_form_with_action' && val === 1) return true;
    if (key === 'has_password_field' && val === 1) return true;
    if (key === 'has_hidden_elements' && val === 1) return true;
    if (key === 'is_https' && val === 0) return true;
    return false;
  };

  const getFeatureClass = (key, val) => {
    if (key === 'url_length') return val > 54 ? 'bad' : 'good';
    if (key === 'is_https') return val === 1 ? 'good' : 'bad';
    if (key === 'num_hyphens') return val > 2 ? 'bad' : val > 0 ? 'neutral' : 'good';
    if (key === 'num_subdomains') return val > 1 ? 'bad' : val === 1 ? 'neutral' : 'good';
    if (val === 1 || val === 0) return isFeatureRisky(key, val) ? 'bad' : 'good';
    return 'neutral';
  };

  const formatFeatureValue = (key, val) => {
    if (key === 'url_length' || key === 'num_hyphens' || key === 'num_subdomains') return val;
    if (val === 1) return 'Yes';
    if (val === 0) return 'No';
    return val;
  };

  return (
    <div className="app-container">
      <div className="glass-panel">
        <div className="badge">🛡️ 100% Client-Side AI · No Server Required</div>
        <h1 className="title">AI Phishing Shield</h1>
        <p className="subtitle">
          Real-time Machine Learning phishing detection — powered entirely in your browser.
          No data is ever sent to a server.
        </p>

        <form className="search-form" onSubmit={checkUrl}>
          <input
            type="text"
            id="url-input"
            className="search-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="e.g. https://secure-login.paypal-update.com"
            disabled={loading}
          />
          <button type="submit" id="analyze-btn" className="search-btn" disabled={loading || !url.trim()}>
            {loading ? 'Scanning...' : 'Analyze'}
          </button>
        </form>

        {error && <div className="error-message">⚠️ {error}</div>}

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
                {isPhishing ? '⚠️ Phishing Detected!' : '✅ Website is Safe'}
              </h2>
              <p className="result-desc">
                Our model is{' '}
                <strong>{isPhishing ? score : (100 - score)}%</strong>{' '}
                confident about this result.
              </p>

              {/* Risk meter */}
              <div className="risk-meter">
                <div className="risk-labels">
                  <span>Safe</span><span>Dangerous</span>
                </div>
                <div className="risk-bar-track">
                  <div
                    className={`risk-bar-fill ${isPhishing ? 'phishing' : 'safe'}`}
                    style={{ width: `${score}%` }}
                  />
                </div>
                <div className="risk-pct">{score}% phishing risk</div>
              </div>
            </div>

            <div className="analyzed-url">
              <span className="analyzed-label">Analyzed URL:</span>
              <span className="analyzed-value">{result.url}</span>
            </div>

            <h3 className="features-title">🔍 Extracted Web Features</h3>
            <div className="features-grid">
              {Object.entries(result.features).map(([key, val]) => (
                <div className="feature-item" key={key}>
                  <span className="feature-label">{formatFeatureName(key)}</span>
                  <span className={`feature-val ${getFeatureClass(key, val)}`}>
                    {formatFeatureValue(key, val)}
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
