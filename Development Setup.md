# Development Setup

multicast_expert uses Poetry to handle setting up for development and uploading the package to PyPi.

## Cheat Sheet

### Setting Up for Local Dev
```
python -m poetry install
```

### Running Tests
```
python -m mypy . # Checks types

# Linux only, allows the loopback tests to pass
sudo ip route add 239.2.2.0/24 dev lo
sudo ip -6 route add table local ff11::/16 dev lo

python -m pytest . # Checks actual code
```

### Running Linting and Formatting
Before commiting changes:
```
./run_linters.sh
```