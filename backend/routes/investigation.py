from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
try:
    from backend.database import get_db
    from backend.investigation.timeline_builder import build_incident_timeline
    from backend.investigation.relationship_builder import build_incident_graph
    from backend.investigation.incident_context import get_incident_context
except ModuleNotFoundError:
    from database import get_db
    from investigation.timeline_builder import build_incident_timeline
    from investigation.relationship_builder import build_incident_graph
    from investigation.incident_context import get_incident_context

router = APIRouter(prefix="/investigation", tags=["Investigation"])

@router.get("/{incident_id}/context")
async def get_context(incident_id: int, db: Session = Depends(get_db)):
    """Retrieves high-level summary, affected entities, and mitigation advice for an incident."""
    context = get_incident_context(db, incident_id=incident_id)
    if "error" in context:
        raise HTTPException(status_code=404, detail=context["error"])
    return context

@router.get("/{incident_id}/timeline")
async def get_timeline(incident_id: int, db: Session = Depends(get_db)):
    """Retrieves the chronological order of logs triggering the incident (event proof)."""
    timeline = build_incident_timeline(db, incident_id=incident_id)
    if not timeline:
        # Check if incident exists
        context = get_incident_context(db, incident_id=incident_id)
        if "error" in context:
            raise HTTPException(status_code=404, detail=context["error"])
    return timeline

@router.get("/{incident_id}/graph")
async def get_graph(incident_id: int, db: Session = Depends(get_db)):
    """Retrieves the User -> Host -> Source IP -> Destination IP/Domain relationship graph."""
    graph = build_incident_graph(db, incident_id=incident_id)
    if not graph or not graph.get("nodes"):
        # Check if incident exists
        context = get_incident_context(db, incident_id=incident_id)
        if "error" in context:
            raise HTTPException(status_code=404, detail=context["error"])
    return graph
