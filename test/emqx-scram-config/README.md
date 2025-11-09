# EMQX SCRAM-SHA-256 Configuration

This directory contains configuration files for testing MQTT 5.0 enhanced authentication with SCRAM-SHA-256.

## Files

- `emqx.conf` - EMQX configuration enabling SCRAM-SHA-256 authentication
- `setup-scram.sh` - Script to add test users to EMQX built-in database

## Usage

### Start EMQX with SCRAM Configuration

```bash
# Stop any existing broker
docker kill mqtt-broker 2>/dev/null || true

# Start EMQX with custom configuration
docker run -d --rm --name mqtt-broker \
  -p 8083:8083 \
  -p 18083:18083 \
  -v $(pwd)/test/emqx-scram-config/emqx.conf:/opt/emqx/etc/emqx.conf \
  emqx/emqx:5.4.0

# Wait for EMQX to start
sleep 10

# Configure SCRAM authentication via HTTP API
./test/emqx-scram-config/setup-scram.sh
```

### Test Credentials

- **Username**: `testuser`
- **Password**: `testpass123`
- **Authentication Method**: `SCRAM-SHA-256`

## EMQX HTTP API

The EMQX HTTP API is available at http://localhost:18083

- Default admin credentials:
  - Username: `admin`
  - Password: `public`

## Notes

- SCRAM-SHA-256 uses PBKDF2 with 4096 iterations
- Enhanced authentication requires MQTT 5.0 clients
- The client must specify `authentication_method = "SCRAM-SHA-256"` in CONNECT
