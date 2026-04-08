from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
from feature_extraction import extract_features
import os

app = FastAPI(title="Phishing Detection API")

# Setup CORS for Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

# Load the trained model
MODEL_PATH = 'model.pkl'
FEATURES_PATH = 'model_features.pkl'

model = None
feature_columns = None

if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURES_PATH)

@app.post("/api/check-url")
def check_url(request: URLRequest):
    if not model or not feature_columns:
        raise HTTPException(status_code=500, detail="Model is not trained yet.")
        
    url = request.url
    features_dict = extract_features(url)
    
    if features_dict is None:
        raise HTTPException(status_code=400, detail="Invalid URL provided.")
        
    # Ensure features are in the right order as expected by the model
    feature_values = [features_dict.get(col, 0) for col in feature_columns]
    
    # Predict
    prediction = model.predict([feature_values])[0]
    
    # Get probabilities
    probability = model.predict_proba([feature_values])[0]
    phishing_prob = probability[1] # Probability of being phishing
    
    result = "Phishing" if prediction == 1 else "Safe"
    
    return {
        "url": url,
        "result": result,
        "phishing_probability": float(phishing_prob),
        "features": features_dict
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
