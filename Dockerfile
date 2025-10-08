FROM python:3.9-slim
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (secrets come from Secret Manager at runtime; never bake keys into the image)
COPY . .

CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 app:app
