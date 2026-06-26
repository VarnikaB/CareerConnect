FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements/base.txt requirements/base.txt
RUN pip install --no-cache-dir --prefix=/install -r requirements/base.txt

FROM python:3.11-slim

RUN useradd --create-home appuser
WORKDIR /app

COPY --from=builder /install /usr/local
COPY . .

RUN mkdir -p instance static/posts static/profile \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["gunicorn", "--config", "gunicorn.conf.py", "run:app"]
