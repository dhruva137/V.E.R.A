"""HTTP surface for projects and saved assistant conversations (engine/projects.py).

Reads need the "read" capability; creating and editing need "collaborate"; running a project's scan needs "scan"
(api/auth.py). The scan itself is the same job the Scan screen starts, tagged with the project when it finishes.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.auth import CURRENT_USER
from engine import projects

router = APIRouter()


def _who() -> str:
    user = CURRENT_USER.get(None) or {}
    return user.get("username") or "local"


class Target(BaseModel):
    kind: str
    value: str
    system: Optional[str] = None


class ProjectIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    purpose: str = ""
    sector: str = "Banking"
    targets: List[Target] = Field(default_factory=list)
    estate: Optional[str] = Field(None, description="An estate register to scan with the targets, or 'demo'.")


class ProjectPatch(BaseModel):
    name: Optional[str] = None
    purpose: Optional[str] = None
    sector: Optional[str] = None
    targets: Optional[List[Target]] = None


@router.get("/projects")
def list_projects():
    return projects.list_all()


@router.post("/projects")
def create_project(body: ProjectIn):
    targets = [t.model_dump() for t in body.targets]
    if body.estate:
        targets.insert(0, {"kind": "estate", "value": body.estate, "system": None})
    try:
        return projects.create(body.name, body.purpose, body.sector, targets, _who())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{pid}")
def get_project(pid: str):
    p = projects.get(pid)
    if p is None:
        raise HTTPException(status_code=404, detail="No such project.")
    return {**p, "scans": projects.scans(pid), "conversations": projects.threads(pid)}


@router.patch("/projects/{pid}")
def patch_project(pid: str, body: ProjectPatch):
    fields = body.model_dump(exclude_none=True)
    if "targets" in fields:
        fields["targets"] = [dict(t) for t in fields["targets"]]
    p = projects.update(pid, **fields)
    if p is None:
        raise HTTPException(status_code=404, detail="No such project.")
    return p


@router.delete("/projects/{pid}")
def delete_project(pid: str):
    if not projects.delete(pid):
        raise HTTPException(status_code=404, detail="No such project.")
    return {"deleted": pid}


@router.post("/projects/{pid}/scan")
def scan_project(pid: str, wait: bool = False):
    """Scan the project's targets (and its estate register, if any) and file the result under the project."""
    from api.routes import FullScanRequest, start_full_scan

    p = projects.get(pid)
    if p is None:
        raise HTTPException(status_code=404, detail="No such project.")
    estate = next((t["value"] for t in p["targets"] if t["kind"] == "estate"), None)
    targets = [t for t in p["targets"] if t["kind"] != "estate"]
    if not targets and not estate:
        raise HTTPException(status_code=400, detail="This project has no targets yet. Add a folder, image, binary or endpoint.")
    return start_full_scan(FullScanRequest(targets=targets, estate=estate, org_persona=p["sector"], wait=wait,
                                           project_id=pid))


class ThreadIn(BaseModel):
    project_id: Optional[str] = None
    title: str = ""
    messages: List[dict] = Field(default_factory=list)


@router.get("/threads")
def list_threads(project: Optional[str] = None):
    return projects.threads(project)


@router.get("/threads/{tid}")
def get_thread(tid: str):
    t = projects.get_thread(tid)
    if t is None:
        raise HTTPException(status_code=404, detail="No such conversation.")
    return t


@router.post("/threads")
def create_thread(body: ThreadIn):
    return projects.save_thread(None, body.project_id, body.messages, _who(), body.title)


@router.put("/threads/{tid}")
def save_thread(tid: str, body: ThreadIn):
    return projects.save_thread(tid, body.project_id, body.messages, _who(), body.title)


@router.delete("/threads/{tid}")
def delete_thread(tid: str):
    if not projects.delete_thread(tid):
        raise HTTPException(status_code=404, detail="No such conversation.")
    return {"deleted": tid}
