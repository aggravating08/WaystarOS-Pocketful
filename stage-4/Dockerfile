FROM python:3.12-slim
WORKDIR /app
COPY server.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
USER 65534:65534
CMD ["python", "server.py"]

