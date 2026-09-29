FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for scikit-learn and postgres
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5001

CMD ["gunicorn", "app:app", "-c", "gunicorn.conf.py"]
