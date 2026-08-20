from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/phishing", tags=["Phishing Protection"])

class PhishingAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=4)

class PhishingDetails(BaseModel):
    https_enabled: bool
    on_blacklist: bool
    typosquatting_detected: bool
    ip_address_url: bool
    suspicious_keywords: bool

class PhishingAnalyzeResponse(BaseModel):
    url: str
    safety_score: float
    risk_level: str
    details: PhishingDetails

@router.post("/analyze", response_model=PhishingAnalyzeResponse)
def analyze_url(req: PhishingAnalyzeRequest):
    url = req.url.lower().strip()
    
    https_enabled = url.startswith("https://")
    on_blacklist = "malicious" in url or "phish" in url or "securevault-update" in url
    
    domain = url.split("://")[-1].split("/")[0] if "://" in url else url.split("/")[0]
    
    # Check if domain looks like an IP
    ip_address_url = all(c.isdigit() or c == '.' for c in domain.replace(":", "")) if domain else False
    
    typosquatting_detected = "goog1e" in domain or "paypa1" in domain or "faceb00k" in domain
    suspicious_keywords = "login" in url or "verify" in url or "update-account" in url or "banking" in url
    
    score = 100.0
    if not https_enabled:
        score -= 20.0
    if typosquatting_detected:
        score -= 40.0
    if ip_address_url:
        score -= 30.0
    if suspicious_keywords:
        score -= 15.0
    if on_blacklist:
        score = 0.0
        
    score = max(0.0, score)
    
    if score >= 80.0:
        risk_level = "LOW"
    elif score >= 50.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
        
    return {
        "url": req.url,
        "safety_score": score,
        "risk_level": risk_level,
        "details": {
            "https_enabled": https_enabled,
            "on_blacklist": on_blacklist,
            "typosquatting_detected": typosquatting_detected,
            "ip_address_url": ip_address_url,
            "suspicious_keywords": suspicious_keywords
        }
    }
