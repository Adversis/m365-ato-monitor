"""In-memory stand-in for an azure.data.tables TableClient."""

import re

from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError


class FakeEntity(dict):
    """A row with ``metadata["etag"]``, like azure.data.tables.TableEntity."""

    def __init__(self, data, etag):
        super().__init__(data)
        self.metadata = {"etag": etag}

_PARTITION_RE = re.compile(r"PartitionKey eq '([^']*)'")
_CMP_RE = re.compile(r"(\w+) (ge|gt|lt|eq) '([^']*)'")


class FakeTable:
    """Supports get, upsert (merge), delete, and the filters the app uses:
    an optional "PartitionKey eq 'X'" and "<field> ge|gt|lt|eq '<value>'" terms."""

    def __init__(self):
        self.rows = {}
        self.etags = {}

    def _bump(self, key):
        self.etags[key] = self.etags.get(key, 0) + 1

    def get_entity(self, partition_key, row_key):
        try:
            row = self.rows[(partition_key, row_key)]
        except KeyError:
            raise ResourceNotFoundError("not found")
        return FakeEntity(row, f"W/\"{self.etags.get((partition_key, row_key), 0)}\"")

    def upsert_entity(self, entity, mode=None):
        key = (entity["PartitionKey"], entity["RowKey"])
        replace = str(getattr(mode, "value", mode) or "").lower() == "replace"
        # MERGE, like the SDK default; REPLACE removes the properties that are not in ``entity``.
        self.rows[key] = dict(entity) if replace else {**self.rows.get(key, {}), **entity}
        self._bump(key)

    def create_entity(self, entity):
        key = (entity["PartitionKey"], entity["RowKey"])
        if key in self.rows:
            raise ResourceExistsError("EntityAlreadyExists")
        self.rows[key] = dict(entity)
        self._bump(key)

    def update_entity(self, entity, mode=None, etag=None, match_condition=None):
        """REPLACE (mode "replace") or MERGE. With an etag: 412 if the row changed since."""
        key = (entity["PartitionKey"], entity["RowKey"])
        if key not in self.rows:
            raise ResourceNotFoundError("not found")
        if etag is not None and etag != f"W/\"{self.etags.get(key, 0)}\"":
            raise ResourceModifiedError("UpdateConditionNotSatisfied")
        replace = str(getattr(mode, "value", mode) or "").lower() == "replace"
        self.rows[key] = dict(entity) if replace else {**self.rows[key], **entity}
        self._bump(key)

    def delete_entity(self, partition_key, row_key):
        self.rows.pop((partition_key, row_key), None)

    def query_entities(self, query_filter, *args, **kwargs):
        m = _PARTITION_RE.search(query_filter)
        # Like the real service: rows sorted by PartitionKey, then RowKey.
        rows = [dict(v) for (pk, _), v in sorted(self.rows.items()) if not m or pk == m.group(1)]
        for field, op, value in _CMP_RE.findall(query_filter):
            if field == "PartitionKey":
                continue
            keep = {"ge": lambda x: x >= value, "gt": lambda x: x > value, "lt": lambda x: x < value,
                    "eq": lambda x: x == value}[op]
            rows = [r for r in rows if keep(str(r.get(field, "")))]
        return rows

    def partition(self, name):
        return {rk: v for (pk, rk), v in self.rows.items() if pk == name}

    def checkpoint(self, content_type):
        from datetime import datetime
        row = self.rows.get(("system", f"checkpoint-{content_type}"))
        return datetime.fromisoformat(row["end"]) if row else None
