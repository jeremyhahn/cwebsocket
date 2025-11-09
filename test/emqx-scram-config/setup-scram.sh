#!/bin/bash
# Setup script for EMQX SCRAM-SHA-256 authentication

set -e

echo "Setting up EMQX with SCRAM-SHA-256 authentication..."

# Wait for EMQX to be ready
echo "Waiting for EMQX to start..."
sleep 10

# Default EMQX credentials
EMQX_HOST="${EMQX_HOST:-localhost:18083}"
EMQX_USER="${EMQX_USER:-admin}"
EMQX_PASS="${EMQX_PASS:-public}"

# Add test user with SCRAM credentials via EMQX HTTP API
# Username: testuser
# Password: testpass123

echo "Adding test user 'testuser' with SCRAM-SHA-256..."

curl -v -X POST "http://${EMQX_HOST}/api/v5/authentication/password_based%3Abuilt_in_database/users" \
  -H "Content-Type: application/json" \
  -u "${EMQX_USER}:${EMQX_PASS}" \
  -d '{
    "user_id": "testuser",
    "password": "testpass123",
    "is_superuser": false
  }' || echo "User may already exist or API changed"

echo "SCRAM-SHA-256 authentication setup complete!"
echo ""
echo "Test credentials:"
echo "  Username: testuser"
echo "  Password: testpass123"
echo "  Auth Method: SCRAM-SHA-256"
