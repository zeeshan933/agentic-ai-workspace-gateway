# Use a lightweight Python base image
FROM python:3.12-slim

# Set the directory inside the container where your app will live
WORKDIR /app

# Install system dependencies required for some Python packages
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install all required Python packages directly
RUN pip install --no-cache-dir \
    Flask \
    Flask-SQLAlchemy \
    Flask-Login \
    Werkzeug \
    pandas \
    openpyxl \
    psycopg2-binary \
    gunicorn \
    python-dotenv \
    requests \
    urllib3

# Copy all your local files (app.py, templates/, static/, etc.) into the container
COPY . .

# Expose the port Gunicorn will run on
EXPOSE 5000

# Set environment variables for Python and Flask
ENV FLASK_APP=app.py
# Prevent Python from writing .pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Run the application using Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "app:app"]
