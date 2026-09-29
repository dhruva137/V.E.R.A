"""
Manages regulatory and threat intelligence announcements.
"""
from __future__ import annotations

import json
import os
from typing import Literal, Optional
from pydantic import BaseModel

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'announcements.json')

class Announcement(BaseModel):
    id: str
    title: str
    body: str
    severity: Literal['info', 'warning', 'critical']
    source: str
    date: str
    category: Literal['regulatory', 'threat', 'migration', 'standard']
    url: Optional[str] = None
    dismissed: bool = False

def _load_data() -> list[Announcement]:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return [Announcement(**item) for item in data]

def _save_data(announcements: list[Announcement]) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump([a.model_dump() for a in announcements], f, indent=2)

def get_announcements() -> list[Announcement]:
    return _load_data()

def get_active_announcements() -> list[Announcement]:
    announcements = _load_data()
    active = [a for a in announcements if not a.dismissed]
    
    severity_order = {'critical': 0, 'warning': 1, 'info': 2}
    # sort by date descending (newest first)
    active.sort(key=lambda a: a.date, reverse=True)
    # sort by severity
    active.sort(key=lambda a: severity_order.get(a.severity, 3))
    
    return active

def dismiss_announcement(announcement_id: str) -> bool:
    announcements = _load_data()
    found = False
    for a in announcements:
        if a.id == announcement_id:
            a.dismissed = True
            found = True
            break
    if found:
        _save_data(announcements)
    return found
