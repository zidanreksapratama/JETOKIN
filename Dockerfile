# Gunakan image Python official yang ringan
FROM python:3.10-slim

# Set working directory di dalam container
WORKDIR /app

# Copy requirements.txt dulu, supaya bisa cache install dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy semua kode ke container
COPY . .

# Set command default untuk run app (ubah sesuai app kamu)
CMD ["python", "app.py"]
