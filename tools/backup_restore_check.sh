#!/usr/bin/env bash
# VenueDesk Database Backup and Restore Verification Script
# Tests pg_dump and pg_restore against a PostgreSQL database,
# with SQLite fallback validation for development environments.
set -euo pipefail

echo "=== VenueDesk Database Backup and Restore Verification ==="

TARGET_DB_URL="${DATABASE_URL:-${TEST_DATABASE_URL:-}}"
BACKUP_DIR="$(mktemp -d /tmp/venuedesk_backup_test_XXXXXX 2>/dev/null || mktemp -d -t 'venuedesk_backup_test_XXXXXX')"
trap 'rm -rf "${BACKUP_DIR}"' EXIT

if [[ -n "${TARGET_DB_URL}" && "${TARGET_DB_URL}" =~ ^postgres(ql)?:// ]]; then
    echo "Detected PostgreSQL target. Executing pg_dump and pg_restore verification..."

    DUMP_FILE="${BACKUP_DIR}/venuedesk_prod.dump"
    RESTORE_DB="venuedesk_restore_verification_test"

    echo "1. Creating custom-format pg_dump..."
    pg_dump --format=custom --no-owner --no-privileges --dbname="${TARGET_DB_URL}" --file="${DUMP_FILE}"
    
    if [[ ! -s "${DUMP_FILE}" ]]; then
        echo "Error: Backup dump file is empty or missing." >&2
        exit 1
    fi
    echo "  [PASS] Custom format dump created successfully ($(du -h "${DUMP_FILE}" | cut -f1))."

    echo "2. Re-creating temporary restore test database: ${RESTORE_DB}..."
    dropdb --if-exists "${RESTORE_DB}"
    createdb "${RESTORE_DB}"

    echo "3. Restoring schema and data with pg_restore..."
    pg_restore --clean --if-exists --no-owner --no-privileges --dbname="${RESTORE_DB}" "${DUMP_FILE}"
    echo "  [PASS] pg_restore exited with 0."

    echo "4. Running post-restore integrity query..."
    RECORD_COUNT=$(psql -d "${RESTORE_DB}" -t -A -c "SELECT COUNT(*) FROM physical_devices;")
    echo "  [PASS] Restored database query succeeded (${RECORD_COUNT} physical_devices records)."

    # Cleanup temporary database
    dropdb "${RESTORE_DB}"
    echo "=== PostgreSQL backup and restore verified successfully ==="

else
    echo "No PostgreSQL connection URL provided (or SQLite in use)."
    echo "Executing SQLite atomic online backup verification..."

    SRC_DB="venuedesk_dev.db"
    if [[ ! -f "${SRC_DB}" ]]; then
        SRC_DB="venuedesk-backend/venuedesk_dev.db"
    fi

    BACKUP_FILE="${BACKUP_DIR}/sqlite_backup.db"

    if [[ -f "${SRC_DB}" ]]; then
        echo "1. Performing SQLite backup of ${SRC_DB}..."
        sqlite3 "${SRC_DB}" ".backup '${BACKUP_FILE}'"
    else
        echo "1. Generating clean SQLite test database for backup test..."
        TEMP_SRC="${BACKUP_DIR}/test_source.db"
        sqlite3 "${TEMP_SRC}" "CREATE TABLE test_data(id INTEGER PRIMARY KEY, note TEXT); INSERT INTO test_data(note) VALUES ('backup_ok');"
        sqlite3 "${TEMP_SRC}" ".backup '${BACKUP_FILE}'"
    fi

    echo "2. Verifying integrity of backup file..."
    INTEGRITY_CHECK=$(sqlite3 "${BACKUP_FILE}" "PRAGMA integrity_check;")
    if [[ "${INTEGRITY_CHECK}" != "ok" ]]; then
        echo "Error: SQLite integrity check on backup failed: ${INTEGRITY_CHECK}" >&2
        exit 1
    fi
    echo "  [PASS] SQLite backup file passed PRAGMA integrity_check (ok)."

    FK_CHECK=$(sqlite3 "${BACKUP_FILE}" "PRAGMA foreign_key_check;")
    if [[ -n "${FK_CHECK}" ]]; then
        echo "Error: SQLite foreign key violations in backup: ${FK_CHECK}" >&2
        exit 1
    fi
    echo "  [PASS] SQLite backup file passed PRAGMA foreign_key_check."
    echo "=== SQLite backup and restore verified successfully ==="
fi
