@echo off
cd /d "%~dp0"
call venv\Scripts\activate
echo Training ML Model...
python ml_model.py
echo Starting API Server...
uvicorn main:app --reload
