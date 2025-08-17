#!/bin/bash

# Script to set up PostgreSQL for the auth service
echo "=== PostgreSQL Setup for Auth Service ==="
echo

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "Error: PostgreSQL is not installed or not in PATH"
    echo "Please install PostgreSQL first:"
    echo "  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib"
    echo "  CentOS/RHEL: sudo yum install postgresql-server postgresql-contrib"
    echo "  macOS: brew install postgresql"
    exit 1
fi

echo "PostgreSQL is installed."
echo

# Check if Docker is available as an alternative
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "Docker and Docker Compose are available."
    echo "You can run the service with Docker using:"
    echo "  make docker-run"
    echo "Or run dependencies with Docker and service locally:"
    echo "  make dev"
    echo
fi

echo "=== Manual PostgreSQL Setup Instructions ==="
echo
echo "1. Connect to PostgreSQL as superuser:"
echo "   sudo -u postgres psql"
echo
echo "2. Run these SQL commands:"
echo "   CREATE USER authuser WITH PASSWORD 'authpass';"
echo "   CREATE DATABASE authdb OWNER authuser;"
echo "   GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;"
echo "   \\q"
echo
echo "3. After creating the user and database, run the service:"
echo "   go run ./cmd/auth"
echo
echo "=== Alternative: Modify Configuration ==="
echo
echo "If you prefer to use an existing PostgreSQL setup:"
echo "1. Edit configs/config.yaml to use your existing PostgreSQL user"
echo "2. Or set environment variables:"
echo "   export DATABASE_USER=your-user"
echo "   export DATABASE_PASSWORD=your-password"
echo "   export DATABASE_NAME=your-database"
echo "   go run ./cmd/auth"
echo
echo "For detailed instructions, see POSTGRESQL_FIX.md"