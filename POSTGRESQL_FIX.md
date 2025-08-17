# Fixing PostgreSQL Connection Issue

## Problem
The error "password authentication failed for user 'authuser'" occurs when the auth service tries to connect to PostgreSQL because the database user 'authuser' doesn't exist or has an incorrect password.

## Solution Options

### Option 1: Use Docker (Recommended)
The easiest way to fix this issue is to use the provided Docker configuration which automatically sets up PostgreSQL with the correct user and database.

1. Run the service with Docker:
   ```bash
   make docker-run
   ```

2. Or run just the dependencies with Docker and the service locally:
   ```bash
   make dev
   ```

### Option 2: Manually Create PostgreSQL User and Database
If you prefer to run PostgreSQL locally, you need to create the required user and database:

1. Connect to PostgreSQL as a superuser:
   ```bash
   sudo -u postgres psql
   ```

2. Create the user and database:
   ```sql
   CREATE USER authuser WITH PASSWORD 'authpass';
   CREATE DATABASE authdb OWNER authuser;
   GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
   \q
   ```

### Option 3: Modify Configuration to Use Existing PostgreSQL Setup
If you already have PostgreSQL running with a different user setup:

1. Edit `configs/config.yaml` to use your existing PostgreSQL user:
   ```yaml
   database:
     host: "localhost"
     port: 5432
     user: "your-postgres-user"      # Change this to your PostgreSQL user
     password: "your-postgres-password"  # Change this to your PostgreSQL password
     name: "your-database-name"       # Change this to your database name
     ssl_mode: "disable"
     max_open_conns: 25
     max_idle_conns: 5
     conn_max_lifetime: "1h"
   ```

### Option 4: Use Environment Variables
The application supports overriding configuration with environment variables:

```bash
export DATABASE_USER=your-postgres-user
export DATABASE_PASSWORD=your-postgres-password
export DATABASE_NAME=your-database-name
go run ./cmd/auth
```

## Troubleshooting

### If you get "Peer authentication failed" errors:
1. Edit the PostgreSQL authentication configuration file (`pg_hba.conf`):
   ```bash
   sudo nano /etc/postgresql/*/main/pg_hba.conf
   ```

2. Find the line that looks like:
   ```
   local   all             all                                     peer
   ```

3. Change it to:
   ```
   local   all             all                                     md5
   ```

4. Restart PostgreSQL:
   ```bash
   sudo systemctl restart postgresql
   ```

### If you get "fe_sendauth: no password supplied" errors:
This means PostgreSQL is configured to require a password but none was provided. Make sure to:
1. Set a password for your PostgreSQL user
2. Use the `-h localhost` flag when connecting with psql to force password authentication
3. Or modify the `pg_hba.conf` file as described above

## Verification
After implementing any of the above solutions, you can verify the connection by running:
```bash
go run ./cmd/auth
```

The service should start without database connection errors.