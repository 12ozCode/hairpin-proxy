# Stage 1: build
FROM python:3.12-alpine AS build

ENV PYTHONUNBUFFERED=1

RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./src/ /app/src/

# Stage 2: slim runtime
FROM python:3.12-alpine AS runtime

WORKDIR /app

# Copy installed Python packages from build stage
COPY --from=build /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /usr/local/include /usr/local/include
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# Copy the app code
COPY ./src/ /app/src/

CMD ["python", "/app/src/main.py"]
