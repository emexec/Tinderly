FROM python:3.13-slim

RUN apt-get update && apt-get install -y curl build-essential && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    ln -s /root/.local/bin/poetry /usr/local/bin/poetry

WORKDIR /app

COPY pyproject.toml poetry.lock* /app/

RUN poetry config virtualenvs.create false \
 && poetry install

COPY . /app

CMD ["poetry", "run", "python", "-m", "uvicorn", "user_service.src.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


