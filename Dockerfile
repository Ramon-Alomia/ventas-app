# 1. Copia y registra tu fullchain en el almacén de CA del sistema
COPY certs/fullchain.crt /usr/local/share/ca-certificates/sl-fullchain.crt

# 2. Instala y actualiza certificados del sistema
RUN apt-get update \
 && apt-get install -y ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 5000

# ④ Arranca Gunicorn para producción
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
