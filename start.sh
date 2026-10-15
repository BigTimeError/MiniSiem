#!/bin/sh

set -e

echo "Waiting for PostgreSQL..."

until python -c "import os; import psycopg; psycopg.connect(os.environ['DATABASE_URL'].replace('postgresql+psycopg://', 'postgresql://')).close()" 2>/dev/null
do
    sleep 1
done

echo "PostgreSQL is ready."

echo "Running database migrations..."

alembic upgrade head

echo "Starting MiniSIEM backend..."

exec uvicorn backend.api.main:app --host 0.0.0.0 --port 8000
