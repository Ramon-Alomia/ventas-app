FROM python:3.11-slim

# ① Instala certificados de sistema para validar CAs públicas
RUN apt-get update \
 && apt-get install -y ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ② Instala dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ③ Copia todo el código (incluye /certs/sl-cert-fullchain.crt)
COPY . .

EXPOSE 5000

# ④ Arranca Gunicorn para producción
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
