#!/usr/bin/env python3
"""T21-only, fail-closed classifier for legacy auth keys in shared Redis DB0."""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from pathlib import Path

UNIAUTH = re.compile(r"^[A-Za-z0-9]{24}$")
ACTIX = re.compile(r"^[A-Za-z0-9]{64}$")
NEW_PREFIXES = (b"auth:external:", b"auth:session:", b"auth:handoff:", b"auth:logout:")


class RedisError(RuntimeError):
    pass


class Redis:
    def __init__(self, host: str, port: int, password_file: str | None) -> None:
        self.sock = socket.create_connection((host, port), timeout=10)
        self.reader = self.sock.makefile("rb")
        if password_file:
            password = Path(password_file).read_bytes().rstrip(b"\r\n")
            if not password:
                raise RedisError("empty Redis password file")
            self.command(b"AUTH", password)

    def close(self) -> None:
        self.reader.close()
        self.sock.close()

    def command(self, *args: bytes):
        message = b"*" + str(len(args)).encode() + b"\r\n"
        for arg in args:
            message += b"$" + str(len(arg)).encode() + b"\r\n" + arg + b"\r\n"
        self.sock.sendall(message)
        return self.reply()

    def reply(self):
        kind = self.reader.read(1)
        if not kind:
            raise RedisError("Redis closed the connection")
        line = self.reader.readline().rstrip(b"\r\n")
        if kind == b"+": return line
        if kind == b"-": raise RedisError(line.decode("utf-8", "replace"))
        if kind == b":": return int(line)
        if kind == b"$":
            length = int(line)
            if length == -1: return None
            value = self.reader.read(length)
            if self.reader.read(2) != b"\r\n": raise RedisError("invalid bulk reply")
            return value
        if kind == b"*":
            length = int(line)
            return None if length == -1 else [self.reply() for _ in range(length)]
        raise RedisError("invalid Redis reply")


def report_key(key: bytes) -> str:
    try: return key.decode("ascii")
    except UnicodeDecodeError: return "hex:" + key.hex()


def json_object(value: bytes | None):
    if value is None: return None
    try:
        parsed = json.loads(value.decode("utf-8"))
        return parsed if type(parsed) is dict else None
    except (UnicodeDecodeError, json.JSONDecodeError): return None


def classify(redis: Redis, key: bytes, rollback_auth_foundation: bool = False) -> dict[str, str]:
    rendered = report_key(key)
    if key.startswith(NEW_PREFIXES):
        category = "migration_created_auth_foundation" if rollback_auth_foundation else "new_auth_foundation_excluded"
        reason = "identified T21 rollback state" if rollback_auth_foundation else "forward cleanup excludes auth:* key families"
        return {"key": rendered, "category": category, "reason": reason}
    try: ascii_key = key.decode("ascii")
    except UnicodeDecodeError:
        return {"key": rendered, "category": "ambiguous", "reason": "non-ASCII key"}
    key_type, ttl = redis.command(b"TYPE", key), redis.command(b"TTL", key)
    payload = json_object(redis.command(b"GET", key) if key_type == b"string" else None)
    valid_ttl = type(ttl) is int and 0 <= ttl <= 86400
    if (UNIAUTH.fullmatch(ascii_key) and key_type == b"string" and valid_ttl and payload is not None
            and set(payload) == {"user_id", "expires_at"} and type(payload["user_id"]) is int
            and -(2**31) <= payload["user_id"] <= 2**31 - 1 and type(payload["expires_at"]) is int
            and -(2**63) <= payload["expires_at"] <= 2**63 - 1):
        return {"key": rendered, "category": "legacy_uniauth", "reason": "exact 24-char legacy string JSON shape"}
    if (ACTIX.fullmatch(ascii_key) and key_type == b"string" and valid_ttl and payload is not None
            and set(payload).issubset({"oauth_state", "redirect"}) and type(payload.get("oauth_state")) is str
            and payload["oauth_state"] != "" and ("redirect" not in payload or type(payload["redirect"]) is str)):
        return {"key": rendered, "category": "legacy_actix_session", "reason": "exact 64-char legacy string JSON shape"}
    return {"key": rendered, "category": "ambiguous", "reason": "does not exactly match an owned legacy format"}


def scan(redis: Redis) -> list[bytes]:
    cursor, keys = b"0", []
    while True:
        result = redis.command(b"SCAN", cursor, b"COUNT", b"200")
        if not isinstance(result, list) or len(result) != 2 or not isinstance(result[0], bytes) or not isinstance(result[1], list):
            raise RedisError("unexpected SCAN result")
        cursor = result[0]
        keys.extend(key for key in result[1] if isinstance(key, bytes))
        if cursor == b"0": return keys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--database", default=0, type=int)
    parser.add_argument("--report", required=True)
    parser.add_argument("--password-file")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--rollback-auth-foundation", action="store_true", help="T21 rollback only: identify the four new auth:* families")
    args = parser.parse_args()
    if args.database != 0: parser.error("T21 supports shared Redis DB0 only")
    redis = Redis(args.host, args.port, args.password_file)
    try:
        entries = [classify(redis, key, args.rollback_auth_foundation) for key in scan(redis)]
        candidate_categories = ({"migration_created_auth_foundation"} if args.rollback_auth_foundation
                                else {"legacy_uniauth", "legacy_actix_session"})
        candidates = [entry["key"] for entry in entries if entry["category"] in candidate_categories]
        ambiguous = [entry["key"] for entry in entries if entry["category"] == "ambiguous"]
        report = {"mode": "execute" if args.execute else "dry-run", "database": 0, "classification": entries,
                  "deletion_candidates": candidates, "ambiguous_keys": ambiguous,
                  "verdict": "STOP" if ambiguous else "READY_FOR_EXPLICIT_DELETE", "deleted": []}
        if args.execute and not ambiguous:
            # Detect a changed candidate before deletion; writers stay stopped throughout.
            for candidate in candidates:
                if classify(redis, candidate.encode("ascii"), args.rollback_auth_foundation)["category"] not in candidate_categories:
                    raise RedisError("candidate changed before deletion")
            if candidates:
                deleted = redis.command(b"DEL", *(key.encode("ascii") for key in candidates))
                if deleted != len(candidates): raise RedisError("DEL count differs from identified candidates")
                report["deleted"] = candidates
        Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"T21 Redis {report['verdict']}: {len(candidates)} candidates, {len(ambiguous)} ambiguous")
        return 3 if ambiguous else 0
    finally:
        redis.close()


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (OSError, RedisError) as error:
        print(f"T21 Redis classifier failed: {error}", file=sys.stderr)
        raise SystemExit(2)
