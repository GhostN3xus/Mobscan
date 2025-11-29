# Mobscan Environment Variables

This document describes all environment variables used by Mobscan.

## Required Variables

These variables **must** be set before running Mobscan:

### `SECRET_KEY` (REQUIRED)

**Description**: Secret key used for JWT token signing and encryption.

**Security**: This is a critical security setting. Never use default values in production.

**How to generate**:
```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

**Example**:
```bash
SECRET_KEY=your-randomly-generated-secret-key-here
```

### `POSTGRES_PASSWORD` (REQUIRED for Docker)

**Description**: Password for PostgreSQL database.

**Security**: Use a strong, randomly generated password.

**Example**:
```bash
POSTGRES_PASSWORD=your-secure-database-password
```

### `PGADMIN_DEFAULT_PASSWORD` (REQUIRED for pgAdmin)

**Description**: Password for pgAdmin web interface.

**Security**: Use a strong password different from database password.

**Example**:
```bash
PGADMIN_DEFAULT_PASSWORD=your-secure-admin-password
```

## Optional Variables

### Database Configuration

#### `POSTGRES_DB`
- **Description**: PostgreSQL database name
- **Default**: `mobscan`
- **Example**: `POSTGRES_DB=mobscan`

#### `POSTGRES_USER`
- **Description**: PostgreSQL username
- **Default**: `mobscan`
- **Example**: `POSTGRES_USER=mobscan`

#### `DATABASE_URL`
- **Description**: Full database connection URL for SQLAlchemy
- **Default**: `postgresql://mobscan:${POSTGRES_PASSWORD}@postgres:5432/mobscan`
- **Example**: `DATABASE_URL=postgresql://user:pass@localhost:5432/dbname`

### Security & Authentication

#### `TOKEN_EXPIRY_MINUTES`
- **Description**: JWT token expiration time in minutes
- **Default**: `30`
- **Example**: `TOKEN_EXPIRY_MINUTES=60`

#### `CORS_ALLOWED_ORIGINS`
- **Description**: Comma-separated list of allowed CORS origins
- **Default**: `http://localhost:3000,http://localhost:8080`
- **Example**: `CORS_ALLOWED_ORIGINS=https://app.example.com,https://api.example.com`

### Redis Configuration

#### `REDIS_HOST`
- **Description**: Redis server hostname
- **Default**: `redis` (Docker) or `localhost`
- **Example**: `REDIS_HOST=localhost`

#### `REDIS_PORT`
- **Description**: Redis server port
- **Default**: `6379`
- **Example**: `REDIS_PORT=6379`

#### `REDIS_DB`
- **Description**: Redis database number
- **Default**: `0`
- **Example**: `REDIS_DB=0`

#### `REDIS_PASSWORD`
- **Description**: Redis authentication password (if required)
- **Default**: None
- **Example**: `REDIS_PASSWORD=your-redis-password`

### Application Settings

#### `MOBSCAN_LOG_LEVEL`
- **Description**: Logging level
- **Options**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- **Default**: `INFO`
- **Example**: `MOBSCAN_LOG_LEVEL=DEBUG`

#### `MOBSCAN_PARALLEL_WORKERS`
- **Description**: Number of parallel workers for scanning
- **Default**: `4`
- **Example**: `MOBSCAN_PARALLEL_WORKERS=8`

#### `MOBSCAN_TIMEOUT`
- **Description**: Scan timeout in seconds
- **Default**: `7200` (2 hours)
- **Example**: `MOBSCAN_TIMEOUT=3600`

### External Services

#### `MOBSF_API_URL`
- **Description**: MobSF API endpoint URL
- **Default**: `http://mobsf:8000`
- **Example**: `MOBSF_API_URL=http://localhost:8001`

#### `MOBSF_API_KEY`
- **Description**: MobSF API authentication key
- **Default**: None
- **Example**: `MOBSF_API_KEY=your-mobsf-api-key`

#### `MITMPROXY_HOST`
- **Description**: mitmproxy server hostname
- **Default**: `mitmproxy`
- **Example**: `MITMPROXY_HOST=localhost`

#### `MITMPROXY_PORT`
- **Description**: mitmproxy server port
- **Default**: `8080`
- **Example**: `MITMPROXY_PORT=8080`

#### `FRIDA_HOST`
- **Description**: Frida server hostname
- **Default**: `frida-server`
- **Example**: `FRIDA_HOST=192.168.1.100`

#### `FRIDA_PORT`
- **Description**: Frida server port
- **Default**: `27042`
- **Example**: `FRIDA_PORT=27042`

### pgAdmin Configuration

#### `PGADMIN_DEFAULT_EMAIL`
- **Description**: Default email for pgAdmin login
- **Default**: `admin@mobscan.dev`
- **Example**: `PGADMIN_DEFAULT_EMAIL=admin@example.com`

## Setup Instructions

### 1. Create .env file

Copy the example environment file:
```bash
cp .env.example .env
```

### 2. Generate Secret Keys

Generate a secure SECRET_KEY:
```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

### 3. Set Required Variables

Edit `.env` and set at minimum:
- `SECRET_KEY`
- `POSTGRES_PASSWORD`
- `PGADMIN_DEFAULT_PASSWORD`

### 4. Verify Configuration

Before starting services, verify all required variables are set:
```bash
grep -E "^(SECRET_KEY|POSTGRES_PASSWORD|PGADMIN_DEFAULT_PASSWORD)=" .env
```

### 5. Start Services

```bash
docker-compose up -d
```

## Security Best Practices

1. **Never commit `.env` files to version control**
   - The `.gitignore` file already excludes `.env`
   - Always use `.env.example` as a template

2. **Use strong, unique passwords**
   - Database passwords: 20+ characters, random
   - Secret keys: Use `secrets.token_urlsafe(32)` or similar
   - Admin passwords: Strong, unique passphrases

3. **Rotate secrets regularly**
   - SECRET_KEY: Rotate every 90 days (invalidates existing tokens)
   - Database passwords: Rotate every 180 days
   - API keys: Rotate as needed

4. **Restrict CORS origins**
   - Only add trusted domains to `CORS_ALLOWED_ORIGINS`
   - Never use wildcards in production

5. **Use environment-specific configurations**
   - Development: `.env.development`
   - Staging: `.env.staging`
   - Production: `.env.production`

## Troubleshooting

### SECRET_KEY not set error

```
ValueError: SECRET_KEY environment variable must be set
```

**Solution**: Set SECRET_KEY in your .env file or environment:
```bash
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
```

### Database connection failed

```
sqlalchemy.exc.OperationalError: could not connect to server
```

**Solution**: Verify database credentials and connection:
```bash
echo $DATABASE_URL
# Check PostgreSQL is running
docker-compose ps postgres
```

### CORS errors in browser

```
Access-Control-Allow-Origin header missing
```

**Solution**: Add your frontend URL to CORS_ALLOWED_ORIGINS:
```bash
CORS_ALLOWED_ORIGINS=http://localhost:3000,https://your-domain.com
```

## Production Deployment

For production deployments:

1. **Use a secrets manager**: AWS Secrets Manager, HashiCorp Vault, etc.
2. **Enable SSL/TLS**: Use HTTPS for all connections
3. **Firewall rules**: Restrict database and Redis access
4. **Monitoring**: Set up alerts for authentication failures
5. **Backup**: Regular backups of database and secrets

## Additional Resources

- [Docker Compose Environment Variables](https://docs.docker.com/compose/environment-variables/)
- [FastAPI Security Best Practices](https://fastapi.tiangolo.com/tutorial/security/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
