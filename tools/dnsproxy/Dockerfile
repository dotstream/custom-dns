FROM python:3.11-slim

# Set a working directory
WORKDIR /app


COPY dnsproxy.py /app/dnsproxy.py
COPY dnsparser.py /app/dnsparser.py


# Create a non-root user for better security
RUN useradd -m dnsuser
USER dnsuser

# Expose DNS port (UDP)
EXPOSE 53/udp

# Default command
ENTRYPOINT ["python", "/app/dnsproxy.py"]
