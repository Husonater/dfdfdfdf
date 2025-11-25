FROM python:3.11-slim

WORKDIR /app

RUN pip install flask gunicorn pyyaml

COPY . .

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
