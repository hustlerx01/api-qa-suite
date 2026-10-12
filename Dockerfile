FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api api
COPY tests tests
COPY pyproject.toml .
RUN useradd -r app
USER app
ENV APP_MODE=fixed
EXPOSE 8000
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
