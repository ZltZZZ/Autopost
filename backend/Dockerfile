FROM python:3.11-alpine3.18

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY requirements.txt /app
RUN pip install -r requirements.txt
RUN pip install prometheus-client

COPY . /app

EXPOSE 8000
CMD ["uvicorn", "server:app", "--host=0.0.0.0", "--port=8000"]
