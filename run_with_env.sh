#!/bin/bash

# Set environment variables to use default PostgreSQL user
# Viper maps environment variables using underscores and uppercase letters
export DATABASE_HOST=localhost
export DATABASE_PORT=5432
export DATABASE_USER=postgres
export DATABASE_PASSWORD=postgres
export DATABASE_NAME=auth_service
export DATABASE_SSL_MODE=disable

# Run the auth service
go run ./cmd/auth