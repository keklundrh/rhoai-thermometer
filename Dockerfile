# RHOAI Thermometer - Streamlit Dashboard
# Using Red Hat Universal Base Image (UBI) 9 with Python 3.11
FROM registry.access.redhat.com/ubi9/python-311:latest

# Set labels
LABEL maintainer="RHOAI Thermometer"
LABEL description="CVE vulnerability dashboard for Red Hat OpenShift AI"

# Set working directory
WORKDIR /app

# Copy application files
COPY app/ /app/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Expose Streamlit default port
EXPOSE 8501

# Run as non-root user (UBI images provide default user)
USER 1001

# Set environment variables for Streamlit
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Run the Streamlit app
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
