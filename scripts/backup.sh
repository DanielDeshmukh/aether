#!/bin/bash
# AETHER Database Backup Script
# Usage: ./backup.sh [daily|weekly|manual]

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/aether}"
DATABASE_URL="${DATABASE_URL:-postgresql://aether:aether_dev_password@localhost:5432/aether}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
BACKUP_TYPE="${1:-manual}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/aether_${BACKUP_TYPE}_${TIMESTAMP}.sql.gz"

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

echo "Starting AETHER database backup..."
echo "Backup type: ${BACKUP_TYPE}"
echo "Backup file: ${BACKUP_FILE}"

# Extract database connection details from URL
DB_HOST=$(echo "${DATABASE_URL}" | sed -n 's|.*@\([^:]*\):.*|\1|p')
DB_PORT=$(echo "${DATABASE_URL}" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
DB_NAME=$(echo "${DATABASE_URL}" | sed -n 's|.*/\([^?]*\).*|\1|p')
DB_USER=$(echo "${DATABASE_URL}" | sed -n 's|://\([^:]*\):.*|\1|p')

# Perform backup using pg_dump
PGPASSWORD="${DATABASE_URL##*:}" pg_dump \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    --format=custom \
    --compress=9 \
    --verbose \
    > "${BACKUP_FILE}" 2>/dev/null

# Verify backup file
if [ -f "${BACKUP_FILE}" ] && [ -s "${BACKUP_FILE}" ]; then
    BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
    echo "Backup completed successfully!"
    echo "File size: ${BACKUP_SIZE}"
else
    echo "ERROR: Backup failed or file is empty"
    exit 1
fi

# Clean up old backups based on retention policy
echo "Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "aether_${BACKUP_TYPE}_*.sql.gz" -mtime +${RETENTION_DAYS} -delete

# List current backups
echo "Current backups:"
ls -lh "${BACKUP_DIR}"/aether_${BACKUP_TYPE}_*.sql.gz 2>/dev/null || echo "No backups found"

echo "Backup process completed."
