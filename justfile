# Justfile to make some common tasks in the vodozemac repo easier.

# List the available recipes.
default:
    just --list

# Create a coverage report using llvm-cov and print to stdout.
coverage:
    cargo llvm-cov nextest

# Create a coverage report for codecov using llvm-cov.
coverage-codecov:
    cargo llvm-cov nextest --codecov --output-path coverage.xml --profile ci

# Format the repo using the nightly version of rustfmt
format:
    cargo +nightly fmt --all
