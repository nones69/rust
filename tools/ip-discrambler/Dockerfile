FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY openapi.yaml ./openapi.yaml

RUN pip install --no-cache-dir .

EXPOSE 8765

ENTRYPOINT ["ipdis"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765"]