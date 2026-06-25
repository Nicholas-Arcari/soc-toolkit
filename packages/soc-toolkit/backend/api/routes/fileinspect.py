from fastapi import APIRouter, File, HTTPException, UploadFile

from core.fileinspector.inspector import inspect_file

router = APIRouter()

# Cap the upload so a huge installer can't exhaust memory; 100 MB covers
# real-world setup files while staying bounded.
_MAX_BYTES = 100 * 1024 * 1024


@router.post("/scan")
async def scan_file(file: UploadFile = File(...)) -> dict:
    """Static analysis of an uploaded file - it is never executed."""
    content = await file.read(_MAX_BYTES + 1)
    if len(content) > _MAX_BYTES:
        raise HTTPException(status_code=413, detail="file too large (max 100 MB)")
    return await inspect_file(file.filename or "unknown", content)
