"""
Audit log management and hold state tracking.
"""
from collections import deque
from datetime import datetime, timezone
import glob
import json
import os
from typing import Any, Dict, List, Optional

from core.models import AuditLogEntry, HeldAction


class AuditManager:
    def __init__(self, log_dir: str = "logs", rotation_minutes: int = 30, max_memory: int = 500):
        self.log_dir = log_dir
        self.rotation_minutes = rotation_minutes
        self.max_memory = max_memory
        self.entries: deque = deque(maxlen=max_memory)
        self.held_actions: Dict[str, HeldAction] = {}
        
        os.makedirs(self.log_dir, exist_ok=True)
        self._load_existing_logs()

    def get_current_log_path(self) -> str:
        now = datetime.now(timezone.utc)
        bucket_minute = (now.minute // self.rotation_minutes) * self.rotation_minutes
        timestamp_str = f"{now.strftime('%Y%m%d_%H')}{bucket_minute:02d}00"
        filename = f"audit_log_{timestamp_str}.jsonl"
        return os.path.join(self.log_dir, filename)

    def _load_existing_logs(self):
        if not os.path.exists(self.log_dir):
            return
        log_files = sorted(glob.glob(os.path.join(self.log_dir, "audit_log_*.jsonl")))
        for filepath in log_files[-3:]:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            self.entries.append(AuditLogEntry(**data))
            except Exception:
                pass

    def log_entry(self, entry: AuditLogEntry):
        self.entries.append(entry)
        current_file = self.get_current_log_path()
        try:
            with open(current_file, "a", encoding="utf-8") as f:
                f.write(entry.model_dump_json() + "\n")
        except Exception:
            pass

    def get_recent(self, limit: int = 100) -> List[AuditLogEntry]:
        return list(self.entries)[-limit:][::-1]

    def register_held_action(self, action: HeldAction):
        self.held_actions[action.id] = action

    def get_held_actions(self, status_filter: Optional[str] = None) -> List[HeldAction]:
        res = list(self.held_actions.values())
        if status_filter:
            res = [a for a in res if a.status == status_filter]
        return sorted(res, key=lambda x: x.timestamp, reverse=True)

    def resolve_held_action(self, hold_id: str, approved: bool, reviewer: str = "security-admin") -> Optional[HeldAction]:
        if hold_id in self.held_actions:
            action = self.held_actions[hold_id]
            action.status = "APPROVED" if approved else "REJECTED"
            action.reviewed_by = reviewer
            action.reviewed_at = datetime.now(timezone.utc).isoformat()
            return action
        return None

    def get_statistics(self) -> Dict[str, Any]:
        total = len(self.entries)
        allowed = sum(1 for e in self.entries if e.allowed)
        blocked = sum(1 for e in self.entries if not e.allowed and not e.is_held)
        held = sum(1 for e in self.entries if e.is_held)
        
        breakdown = {}
        for e in self.entries:
            if e.error_code:
                breakdown[e.error_code] = breakdown.get(e.error_code, 0) + 1

        return {
            "total_requests": total,
            "allowed_count": allowed,
            "blocked_count": blocked,
            "held_count": held,
            "pass_rate_pct": round((allowed / total * 100), 1) if total > 0 else 100.0,
            "rejections_by_error_code": breakdown
        }
