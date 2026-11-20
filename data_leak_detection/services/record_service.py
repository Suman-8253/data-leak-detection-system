"""
Record service — business logic for encrypted secure records.
"""
from database.repositories import RecordRepository
from security.encryption import encrypt, decrypt, is_key_configured
from security.input_validation import validate_title, validate_content
from security.injection_detection import check_and_log_injection
from security.audit_logger import audit_action
import psycopg2


def create_record(owner_id, title, content):
    """
    Create a new encrypted record.
    Returns (success, record_or_error).
    """
    ok, err = validate_title(title)
    if not ok:
        return False, err

    ok, err = validate_content(content)
    if not ok:
        return False, err

    if not is_key_configured():
        return False, "Encryption is not configured. Contact an administrator."

    # Monitor inputs
    check_and_log_injection(title, 'record_title', owner_id)
    check_and_log_injection(content, 'record_content', owner_id)

    # Encrypt content
    try:
        ciphertext, nonce = encrypt(content)
    except Exception as e:
        return False, "Encryption failed. Please try again."

    # Store in database
    record = RecordRepository.create_record(
        owner_id=owner_id,
        title=title,
        encrypted_payload=psycopg2.Binary(ciphertext),
        nonce=psycopg2.Binary(nonce),
        version=1
    )

    if not record:
        return False, "Failed to create record."

    audit_action(owner_id, 'record_created', 'secure_record', record['id'])
    return True, record


def get_record(record_id, requesting_user_id):
    """
    Get and decrypt a record. Verifies ownership.
    Returns (success, record_dict_or_error).
    """
    record = RecordRepository.find_by_id(record_id)
    if not record:
        return False, "Record not found."

    if str(record['owner_id']) != str(requesting_user_id):
        audit_action(requesting_user_id, 'unauthorized_record_access',
                     'secure_record', record_id, outcome='denied')
        return False, "Access denied."

    # Decrypt payload
    try:
        plaintext = decrypt(
            bytes(record['encrypted_payload']),
            bytes(record['encryption_nonce'])
        )
    except Exception:
        return False, "Decryption failed. Data may be corrupted."

    result = dict(record)
    result['decrypted_content'] = plaintext
    # Remove raw encrypted data from response
    del result['encrypted_payload']
    del result['encryption_nonce']

    audit_action(requesting_user_id, 'record_viewed', 'secure_record', record_id)
    return True, result


def list_records(owner_id, page=1, per_page=20, search=None):
    """
    List records for an owner with pagination.
    Returns (records, total_count, total_pages).
    """
    offset = (page - 1) * per_page
    records = RecordRepository.list_by_owner(owner_id, per_page, offset, search)
    total = RecordRepository.count_by_owner(owner_id, search)
    total_pages = max(1, (total + per_page - 1) // per_page)
    return records, total, total_pages


def update_record(record_id, title, content, requesting_user_id):
    """
    Update a record. Verifies ownership and re-encrypts content.
    """
    record = RecordRepository.find_by_id(record_id)
    if not record:
        return False, "Record not found."

    if str(record['owner_id']) != str(requesting_user_id):
        audit_action(requesting_user_id, 'unauthorized_record_update',
                     'secure_record', record_id, outcome='denied')
        return False, "Access denied."

    ok, err = validate_title(title)
    if not ok:
        return False, err

    ok, err = validate_content(content)
    if not ok:
        return False, err

    try:
        ciphertext, nonce = encrypt(content)
    except Exception:
        return False, "Encryption failed."

    updated = RecordRepository.update_record(
        record_id, title,
        psycopg2.Binary(ciphertext),
        psycopg2.Binary(nonce),
        version=1
    )

    audit_action(requesting_user_id, 'record_updated', 'secure_record', record_id)
    return True, updated


def delete_record(record_id, requesting_user_id):
    """
    Delete a record. Verifies ownership.
    """
    record = RecordRepository.find_by_id(record_id)
    if not record:
        return False, "Record not found."

    if str(record['owner_id']) != str(requesting_user_id):
        audit_action(requesting_user_id, 'unauthorized_record_delete',
                     'secure_record', record_id, outcome='denied')
        return False, "Access denied."

    RecordRepository.delete_record(record_id)
    audit_action(requesting_user_id, 'record_deleted', 'secure_record', record_id)
    return True, "Record deleted."


def count_records():
    """Count all records."""
    return RecordRepository.count_all()


def count_user_records(owner_id):
    """Count records for a specific user."""
    return RecordRepository.count_by_owner(owner_id)
