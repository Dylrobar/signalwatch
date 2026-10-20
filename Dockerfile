FROM python:3.12-slim-bookworm
# Match backup tools to the PostgreSQL 16 deployment and CI restore rehearsal.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl --fail --silent --show-error https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/keyrings/postgresql.asc \
    && printf '%s\n' 'deb [signed-by=/usr/share/keyrings/postgresql.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main' > /etc/apt/sources.list.d/postgresql.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nmap postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements-deploy.txt && pip install --no-cache-dir --no-deps .
EXPOSE 8765
CMD ["signalwatch", "--config", "/data/config.json", "runtime", "--host", "0.0.0.0"]
