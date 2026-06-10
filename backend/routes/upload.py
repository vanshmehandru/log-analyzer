import io
import pandas as pd
from typing import List, Optional
from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from sqlalchemy.orm import Session

try:
    from backend.database import get_db
    from backend.services.mapping_loader import load_mapping
    from backend.services.header_extractor import extract_headers
    from backend.services.normalizer import build_translation_dictionary, normalize_dataframe
    from backend.services.categorizer import categorize_dataframe
    from backend.services.database_service import (
        create_upload,
        store_raw_logs,
        store_header_mappings,
        store_normalized_logs
    )
    from backend.correlation.engine import run_correlation
except ModuleNotFoundError:
    from database import get_db
    from services.mapping_loader import load_mapping
    from services.header_extractor import extract_headers
    from services.normalizer import build_translation_dictionary, normalize_dataframe
    from services.categorizer import categorize_dataframe
    from services.database_service import (
        create_upload,
        store_raw_logs,
        store_header_mappings,
        store_normalized_logs
    )
    from correlation.engine import run_correlation

router = APIRouter(prefix="/upload", tags=["Uploads"])

mapping_config = load_mapping()

@router.post("")
async def upload_files(
    file1: Optional[UploadFile] = None,
    file2: Optional[UploadFile] = None,
    file3: Optional[UploadFile] = None,
    db: Session = Depends(get_db)
):
    """Ingests three mandatory log files, normalizes, categorizes, stores, and runs correlation rules."""
    # Validate that all three files are provided
    if not file1 or not file2 or not file3:
        raise HTTPException(
            status_code=400, 
            detail="Please upload all three log sources."
        )
        
    upload_results = []
    total_records = 0
    created_uploads = []
    
    try:
        files = [file1, file2, file3]
        for file in files:
            if not file.filename.endswith('.csv'):
                raise HTTPException(
                    status_code=400, 
                    detail=f"Only CSV files are supported. File '{file.filename}' is invalid."
                )
                
            # Step 1: Create Upload Record
            upload_record = create_upload(db, file_name=file.filename)
            created_uploads.append(upload_record)
            
            # Read file bytes
            file_bytes = await file.read()
            
            # Step 2: Store Raw Logs (original CSV rows)
            # Use seek to beginning in case we need to read it again
            df_raw = pd.read_csv(io.BytesIO(file_bytes))
            raw_records = df_raw.to_dict(orient="records")
            store_raw_logs(db, upload_id=upload_record.id, records=raw_records)
            
            # Update record count
            upload_record.total_records = len(raw_records)
            total_records += len(raw_records)
            
            # Step 3: Extract headers
            original_headers = extract_headers(file_bytes)
            
            # Step 4: Store header mappings
            translation_dict = build_translation_dictionary(original_headers, mapping_config)
            store_header_mappings(db, upload_id=upload_record.id, translation_dict=translation_dict)
            
            # Step 5: Normalize fields
            df_normalized = normalize_dataframe(df_raw, translation_dict)
            
            # Step 6: Categorize events
            df_categorized = categorize_dataframe(df_normalized)
            
            # Convert to standard python dicts for ingestion
            normalized_headers = df_categorized.columns.tolist()
            normalized_records = []
            for _, row in df_categorized.iterrows():
                record = {}
                for col in normalized_headers:
                    val = row[col]
                    if pd.isna(val):
                        val = None
                    elif hasattr(val, "item"):
                        val = val.item()
                    record[col] = val
                normalized_records.append(record)
                
            # Step 7: Store normalized records
            store_normalized_logs(db, upload_id=upload_record.id, records=normalized_records)
            
            # Mark upload as completed
            upload_record.status = "completed"
            db.commit()
            
            upload_results.append({
                "file_name": file.filename,
                "record_count": upload_record.total_records,
                "status": "Success"
            })
            
        # Step 8 & 9: Run correlation engine
        new_incidents = []
        try:
            # Correlate all logs in the database
            new_incidents = run_correlation(db)
        except Exception as corr_err:
            print(f"Batch correlation failed: {corr_err}")
            
        return {
            "files": upload_results,
            "total_records": total_records,
            "total_incidents": len(new_incidents)
        }
        
    except Exception as err:
        # Mark all created uploads in this batch as failed on exception
        db.rollback()
        for upload_rec in created_uploads:
            try:
                # Refresh object state
                db.refresh(upload_rec)
                upload_rec.status = "failed"
                db.commit()
            except Exception:
                db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to process log batch: {str(err)}")

@router.post("/clear")
async def clear_database_endpoint(db: Session = Depends(get_db)):
    """Deletes all uploads, raw logs, normalized logs, and incidents to reset database."""
    try:
        from models.uploads import Upload
        from models.raw_logs import RawLog
        from models.normalized_logs import NormalizedLog
        from models.header_mappings import HeaderMapping
        from models.incidents import Incident
        from models.incident_evidence import IncidentEvidence
    except ModuleNotFoundError:
        from backend.models.uploads import Upload
        from backend.models.raw_logs import RawLog
        from backend.models.normalized_logs import NormalizedLog
        from backend.models.header_mappings import HeaderMapping
        from backend.models.incidents import Incident
        from backend.models.incident_evidence import IncidentEvidence

    try:
        db.query(IncidentEvidence).delete()
        db.query(Incident).delete()
        db.query(NormalizedLog).delete()
        db.query(RawLog).delete()
        db.query(HeaderMapping).delete()
        db.query(Upload).delete()
        db.commit()
        return {"status": "success", "message": "All database records have been deleted successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to clear database: {str(e)}")
