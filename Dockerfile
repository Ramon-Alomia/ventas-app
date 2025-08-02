FROM python:3.11-slim

# Copia SOLO la CA intermedia
COPY certs/intermediate.crt /usr/local/share/ca-certificates/intermediate.crt

# Instala y registra nuevas CAs
RUN apt-get update \
 && apt-get install -y ca-certificates \
 && update-ca-certificates --verbose \
 && rm -rf /var/lib/apt/lists/*


ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# 3. Instala y actualiza certificados del sistema
RUN apt-get update \
 && apt-get install -y ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# 4. Prepara el directorio de la app
WORKDIR /app

# 5. Instala dependencias de Python
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copia el resto del código
COPY . .

# 7. Expone el puerto que usa Flask/Gunicorn
EXPOSE 5000

# 8. Arranca Gunicorn en modo producción capturando stdout/stderr
CMD ["gunicorn", "app:app", \
     "--bind", "0.0.0.0:5000", \
     "--log-level", "debug", \
     "--capture-output", \
     "--enable-stdio-inheritance"]
