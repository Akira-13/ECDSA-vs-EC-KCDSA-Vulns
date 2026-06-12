FROM python:3.11-slim
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ec.py ec_kcdsa.py ./
COPY challenge_kcdsa_reuse/server.py ./server.py
RUN sed -i 's/from \.ec import/from ec import/g' ec_kcdsa.py
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 server.py"]
