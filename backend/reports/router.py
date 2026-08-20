from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List
import io
import sqlite3
from db import get_db

router = APIRouter(prefix="/api/reports", tags=["Reports"])

mock_reports = [
    {
        "id": "rep_001",
        "created_at": "2026-08-08T09:00:00Z",
        "report_type": "SECURITY_SUMMARY",
        "filename": "SecureVault_Report_rep_001.pdf"
    }
]

class ReportSummary(BaseModel):
    id: str
    created_at: str
    report_type: str
    filename: str

class GenerateReportRequest(BaseModel):
    report_type: str

@router.get("/list", response_model=List[ReportSummary])
def get_reports_list():
    return mock_reports

@router.post("/generate", response_model=ReportSummary, status_code=201)
def generate_report(req: GenerateReportRequest):
    new_report = {
        "id": f"rep_{len(mock_reports) + 1:03d}",
        "created_at": "2026-08-08T09:20:00Z",
        "report_type": req.report_type,
        "filename": f"SecureVault_Report_rep_{len(mock_reports) + 1:03d}.pdf"
    }
    mock_reports.append(new_report)
    return new_report

def generate_pdf_bytes(report_id, report_type, firewall_enabled, files_protected, active_threats, recommendations):
    title = f"SecureVault Security Report - {report_type}"
    lines = [
        f"Report ID: {report_id}",
        "Generated at: 2026-08-08T09:20:00Z",
        "",
        "SYSTEM STATUS SUMMARY:",
        f"  - Firewall Status: {'ENABLED' if firewall_enabled else 'DISABLED'}",
        f"  - Files Protected: {files_protected}",
        f"  - Unresolved Threats: {active_threats}",
        "",
        "REMEDIAL ACTIONS RECOMMENDATIONS:"
    ]
    
    if not recommendations:
        lines.append("  No active threats or recommendations. System is secure.")
    else:
        for idx, rec in enumerate(recommendations, 1):
            lines.append(f"  {idx}. [{rec['status']}] {rec['title']} - {rec['description']}")
            
    content_lines = []
    content_lines.append("BT")
    content_lines.append("/F1 14 Tf")
    content_lines.append("50 750 Td")
    content_lines.append(f"({title}) Tj")
    content_lines.append("/F1 10 Tf")
    
    for line in lines:
        escaped_line = line.replace("(", "\\(").replace(")", "\\)")
        content_lines.append("0 -18 Td")
        content_lines.append(f"({escaped_line}) Tj")
        
    content_lines.append("ET")
    content_stream = "\n".join(content_lines)
    
    objects = []
    objects.append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj")
    objects.append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj")
    objects.append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj")
    
    content_len = len(content_stream)
    objects.append(f"4 0 obj\n<< /Length {content_len} >>\nstream\n{content_stream}\nendstream\nendobj")
    objects.append("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj")
    
    pdf_out = bytearray()
    pdf_out.extend(b"%PDF-1.4\n")
    
    offsets = {}
    for obj_idx in range(1, 6):
        offsets[obj_idx] = len(pdf_out)
        pdf_out.extend(objects[obj_idx - 1].encode('utf-8'))
        pdf_out.extend(b"\n")
        
    xref_pos = len(pdf_out)
    pdf_out.extend(b"xref\n0 6\n")
    pdf_out.extend(b"0000000000 65535 f \n")
    for obj_idx in range(1, 6):
        pdf_out.extend(f"{offsets[obj_idx]:010d} 00000 n \n".encode('utf-8'))
        
    pdf_out.extend(b"trailer\n<< /Size 6 /Root 1 0 R >>\n")
    pdf_out.extend(b"startxref\n")
    pdf_out.extend(f"{xref_pos}\n".encode('utf-8'))
    pdf_out.extend(b"%%EOF\n")
    
    return pdf_out

@router.get("/download/{report_id}")
def download_report(report_id: str):
    found = next((r for r in mock_reports if r["id"] == report_id), None)
    if not found:
        raise HTTPException(status_code=404, detail="Report not found")
        
    # Query current dynamic stats
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Firewall status
    cursor.execute("SELECT enabled FROM firewall_status")
    fw_row = cursor.fetchone()
    firewall_enabled = (fw_row["enabled"] == 1) if fw_row else False
    
    # 2. Files protected
    cursor.execute("SELECT COUNT(*) as count FROM encrypted_files")
    files_protected = cursor.fetchone()["count"]
    
    # 3. Recommendations
    try:
        cursor.execute("SELECT title, description, status FROM threat_recommendations")
        recs_rows = cursor.fetchall()
    except Exception:
        recs_rows = []
        
    conn.close()
    
    recommendations = [
        {"title": r["title"], "description": r["description"], "status": r["status"]}
        for r in recs_rows
    ]
    active_threats = sum(1 for r in recommendations if r["status"] == "PENDING")
    
    pdf_bytes = generate_pdf_bytes(
        report_id=report_id,
        report_type=found["report_type"],
        firewall_enabled=firewall_enabled,
        files_protected=files_protected,
        active_threats=active_threats,
        recommendations=recommendations
    )
    
    stream = io.BytesIO(pdf_bytes)
    return StreamingResponse(
        stream,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={found['filename']}"}
    )
