"""Read-only projection of explicitly recorded paired HTTP database restores."""
from __future__ import annotations

from datetime import datetime, timedelta
import json
import re
import time


SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def public_record(name, value):
    try:
        record = json.loads(value)
        if not isinstance(record, dict) or type(record.get('schema_version')) is not int or record['schema_version'] != 1:
            raise ValueError
        backup = record['backup_id']
        if not isinstance(backup, str) or not SAFE_ID.fullmatch(backup) or name != 'restore:' + backup:
            raise ValueError
        if not isinstance(record['restore_id'], str) or not DIGEST.fullmatch(record['restore_id']):
            raise ValueError
        if record['verification_scope'] != 'paired_database_snapshots':
            raise ValueError
        if type(record['stream_count']) is not int or record['stream_count'] < 0:
            raise ValueError
        for field in ('marked_at', 'snapshot_at'):
            stamp = record[field]
            if not isinstance(stamp, str) or not 20 <= len(stamp) <= 32:
                raise ValueError
            parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if parsed.utcoffset() != timedelta(0):
                raise ValueError
        return {key: record[key] for key in ('restore_id', 'backup_id', 'snapshot_at', 'marked_at',
                                             'stream_count', 'verification_scope')}
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError('Invalid HTTP restore history') from None


def list_restores(db, *, page=1, limit=20):
    if type(page) is not int or not 1 <= page <= 1000000 or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('Invalid HTTP restore page')
    # History is global to the paired HTTP database, not filtered by today's
    # configured streams. Only return display fields, never paths or digests.
    deadline = time.monotonic() + 5
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        total = db.execute("SELECT count(*) FROM http_analysis_meta WHERE name GLOB 'restore:*'").fetchone()[0]
        pages = max(1, (total + limit - 1) // limit)
        page = min(page, pages)
        rows = db.execute("SELECT name,value FROM http_analysis_meta WHERE name GLOB 'restore:*' "
                          "ORDER BY julianday(json_extract(value,'$.marked_at')) DESC,name DESC LIMIT ? OFFSET ?",
                          (limit, (page - 1) * limit))
        return {'items': [public_record(row[0], row[1]) for row in rows],
                'page': page, 'limit': limit, 'total': total, 'total_pages': pages}
    finally:
        db.set_progress_handler(None, 0)
