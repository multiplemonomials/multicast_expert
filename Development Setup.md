# Development Setup

multicast_expert uses Poetry to handle setting up for development and uploading the package to PyPi.

## Cheat Sheet

### Setting Up for Local Dev
```
python -m poetry install
python -m poetry shell # This activates a virtual environment containing the dependencies
```

### Running Tests
```
python -m mypy . # Checks types
python -m pytest . # Checks actual code
```

### Uploading to PyPi
```
python -m poetry publish --build
```