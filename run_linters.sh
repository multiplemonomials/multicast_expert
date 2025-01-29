#!/bin/bash -e

echo "Formatting with ruff..."
poetry run ruff format .

echo "Linting with ruff..."
poetry run ruff check --fix .

echo "Type checking with mypy..."
poetry run mypy -p multicast_expert

echo "Checking docs with docsig..."
poetry run docsig multicast_expert

if ! [ -x "$(command -v pyright)" ]; then
   echo "Pyright not found. Please install nodejs, then run 'npm install -g pyright'.";
   exit 1;
fi

# Note: use 'poetry run' so it runs inside the venv, even though pyright is not installed through poetry
poetry run pyright multicast_expert tests