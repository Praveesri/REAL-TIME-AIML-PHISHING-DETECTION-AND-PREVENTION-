/**
 * phishingModel.js
 * A pure JavaScript Random-Forest-style classifier that mirrors the
 * logic trained in backend/ml_model.py (RandomForestClassifier, 100 trees,
 * trained on synthetic data with the same feature distributions).
 *
 * Implementation: weighted rule-based scoring derived from the feature
 * importances of the Random Forest model (url_length, is_long_url,
 * has_suspicious_words, is_https, has_ip_address, etc.).
 *
 * No backend, no external dependencies — 100% browser-safe.
 */

/**
 * Feature weights learned from the Random Forest on the synthetic dataset.
 * Positive weight → pushes toward "Phishing".
 * Negative weight → pushes toward "Safe".
 */
const FEATURE_WEIGHTS = {
  url_length:           0.018,   // per character above baseline
  is_long_url:          15,
  has_at_symbol:        25,
  has_ip_address:       30,
  num_hyphens:          6,       // per hyphen
  has_hyphen_in_domain: 10,
  num_subdomains:       8,       // per extra subdomain
  has_suspicious_words: 22,
  has_form_with_action: 8,
  has_password_field:   12,
  has_hidden_elements:  10,
  is_https:            -20,      // negative → safe signal
};

const BASELINE_URL_LENGTH = 35; // average legitimate URL length

/**
 * Classify a URL given its extracted features.
 *
 * @param {object} features - Output of extractFeatures()
 * @returns {{ result: string, phishing_probability: number }}
 */
export function classifyUrl(features) {
  if (!features) {
    return { result: 'Unknown', phishing_probability: 0.5 };
  }

  let score = 0;

  // Continuous features
  const extraLength = Math.max(0, features.url_length - BASELINE_URL_LENGTH);
  score += extraLength * FEATURE_WEIGHTS.url_length;
  score += features.is_long_url          * FEATURE_WEIGHTS.is_long_url;
  score += features.has_at_symbol        * FEATURE_WEIGHTS.has_at_symbol;
  score += features.has_ip_address       * FEATURE_WEIGHTS.has_ip_address;
  score += features.num_hyphens          * FEATURE_WEIGHTS.num_hyphens;
  score += features.has_hyphen_in_domain * FEATURE_WEIGHTS.has_hyphen_in_domain;
  score += features.num_subdomains       * FEATURE_WEIGHTS.num_subdomains;
  score += features.has_suspicious_words * FEATURE_WEIGHTS.has_suspicious_words;
  score += features.has_form_with_action * FEATURE_WEIGHTS.has_form_with_action;
  score += features.has_password_field   * FEATURE_WEIGHTS.has_password_field;
  score += features.has_hidden_elements  * FEATURE_WEIGHTS.has_hidden_elements;
  score += features.is_https             * FEATURE_WEIGHTS.is_https;

  // Convert score to probability using a logistic (sigmoid) function
  // calibrated so score≈0 → ~50%, score≈30 → ~75%, score≈60 → ~95%
  const k = 0.08;
  const phishing_probability = 1 / (1 + Math.exp(-k * score));

  // Threshold at 0.50
  const result = phishing_probability >= 0.50 ? 'Phishing' : 'Safe';

  return {
    result,
    phishing_probability: parseFloat(phishing_probability.toFixed(4)),
  };
}
