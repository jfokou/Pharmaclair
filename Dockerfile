FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY . /app

EXPOSE 8000 8080

CMD ["python", "-u", "pharmaclair.py"]
