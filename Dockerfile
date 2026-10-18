FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
EXPOSE 8765
CMD ["signalwatch", "--config", "/data/config.json", "serve", "--host", "0.0.0.0"]
