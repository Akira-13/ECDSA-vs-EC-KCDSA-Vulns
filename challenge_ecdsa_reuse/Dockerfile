FROM python:3.11-slim
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ec.py ecdsa.py ./
COPY challenge_ecdsa_reuse/server.py ./server.py
RUN sed -i 's/from \.ec import/from ec import/g' ecdsa.py
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 server.py"]
