FROM python:3.11-slim

# 1) Instala certificados de sistema para validar CAs públicas
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2) Copia requirements e instala dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3) Copia TODO el código de la app, incluida la carpeta certs/
COPY . .

# 4) Expone puerto y define comando de arranque
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
