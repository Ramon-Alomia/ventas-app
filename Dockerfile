FROM python:3.11-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# DEBUG: listar y verificar cadena de certificados
RUN ls -R /app/certs
RUN head -n 20 /app/certs/sl-cert-fullchain.crt
RUN tail -n 20 /app/certs/sl-cert-fullchain.crt

EXPOSE 5000
CMD ["gunicorn","--bind","0.0.0.0:5000","app:app"]
