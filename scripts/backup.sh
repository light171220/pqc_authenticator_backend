#!/bin/bash

set -e

BACKUP_DIR="${BACKUP_DIR:-./backups}"
DATABASE_PATH="${DATABASE_PATH:-./data/authenticator.db}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="pqc_authenticator_backup_${TIMESTAMP}"

echo "Creating backup: ${BACKUP_NAME}"

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Create backup archive
tar -czf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" \
    --exclude='logs/*' \
    --exclude='backups/*' \
    data/ configs/

echo "Backup created: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

# Keep only last 7 backups
find "${BACKUP_DIR}" -name "pqc_authenticator_backup_*.tar.gz" -mtime +7 -delete

echo "Backup completed successfully!"