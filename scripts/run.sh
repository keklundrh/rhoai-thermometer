#!/bin/bash
# Run the RHOAI Thermometer dashboard

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run Streamlit app from app directory
streamlit run app/app.py
