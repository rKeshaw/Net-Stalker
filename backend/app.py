import time
import re
import json
import asyncio
import os
import logging
import uuid
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from pydantic import BaseModel, field_validator
from contextlib import asynccontextmanager
from analyzer import BasicPhishingAnalyzer
from email_analyzer import EmailPhishingAnalyzer
from llm_analyzer import GroqPhishingAnalyzer
from external_apis import ExternalAPIAggregator
from behavioral_analyzer import BehavioralAnalyzer 
from task_manager import task_manager, TaskStatus
from qr_analyzer import QRCodeAnalyzer
from report_generator import ForensicReportGenerator
from fastapi.responses import FileResponse
from pcap_analyzer import PCAPAnalyzer
from logging_config import get_logger, request_id_ctx, setup_logging

setup_logging()
logger = get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    async def cleanup_tasks():
        while True:
            await asyncio.sleep(600)  
            try:
                task_manager.cleanup_old_tasks(max_age_minutes=60)
            except Exception as e:
                logger.exception("Error during background task cleanup")
    
    cleanup_task = asyncio.create_task(cleanup_tasks())
    api_config = api_aggregator.validate_configuration()
    logger.info("External API configuration loaded", extra=api_config)
    if not api_config.get("configured"):
        logger.warning("No external API keys configured; external intelligence checks are disabled")
    yield  

    cleanup_task.cancel()  
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

app = FastAPI(title="Phishing Detection API - Prototype", lifespan=lifespan)

_cors_origins_env = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
CORS_ALLOW_ORIGINS = [origin.strip() for origin in _cors_origins_env.split(",") if origin.strip()] if _cors_origins_env else ["*"]
CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "false").strip().lower() == "true"
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(10 * 1024 * 1024)))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))
_rate_limit_store = {}

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _validate_upload_size(file: UploadFile):
    if file.size is not None and file.size > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"Upload exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES} bytes")

def _safe_join(base_dir: str, filename: str) -> str:
    safe_filename = os.path.basename(filename)
    target_path = os.path.realpath(os.path.join(base_dir, safe_filename))
    base_path = os.path.realpath(base_dir)
    if not target_path.startswith(base_path + os.sep):
        raise HTTPException(status_code=400, detail="Invalid file path")
    return target_path

def _enforce_rate_limit(client_key: str):
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    requests = _rate_limit_store.get(client_key, [])
    requests = [ts for ts in requests if ts >= window_start]
    if len(requests) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    requests.append(now)
    _rate_limit_store[client_key] = requests

class URLRequest(BaseModel):
    url: str
    use_external_apis: bool = True
    async_mode: bool = True
    enable_behavioral: bool = True
    enable_live_capture: bool = True
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError('URL must be a non-empty string')
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class TextAnalysisRequest(BaseModel):
    text: str
    
    @field_validator('text')
    @classmethod
    def validate_text(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError('Text must be a non-empty string')
        if len(v) < 10:
            raise ValueError('Text must be at least 10 characters')
        return v

class AnalysisResponse(BaseModel):
    analysis_type: str
    input_data: str
    features: dict
    llm_analysis: dict
    external_apis: dict = {}
    processing_time: float
    timestamp: str

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str

# Initialize analyzers
llm_analyzer = GroqPhishingAnalyzer()
api_aggregator = ExternalAPIAggregator()
behavioral_analyzer = BehavioralAnalyzer(timeout=30) 
qr_analyzer = QRCodeAnalyzer()
report_gen = ForensicReportGenerator()
pcap_analyzer = PCAPAnalyzer()

@app.get("/")
async def root():
    available_apis = api_aggregator.get_available_apis()
    
    return {
        "name": "Phishing Detection API - Prototype",
        "version": "0.4.1",
        "features": [
            "url_analysis", 
            "email_analysis", 
            "text_analysis", 
            "external_api_integration",
            "background_processing",
            "real_time_progress",
            "behavioral_analysis"
        ],
        "external_apis": available_apis,
        "status": "operational"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/apis")
async def list_apis():
    """List available external APIs"""
    return {"apis": api_aggregator.get_available_apis()}

def process_screenshot_url(features, base_url):
    """Convert local screenshot path to accessible URL"""
    if "screenshot_path" in features and features["screenshot_path"]:
        filename = os.path.basename(features["screenshot_path"])
        base = str(base_url).rstrip('/')
        features["screenshot_url"] = f"{base}/screenshot/{filename}"
    return features

def extract_urls_from_text(text: str, max_urls: int = 5):
    url_pattern = r"http[s]?://[^\s<>\"'\)]+"
    urls = re.findall(url_pattern, text or "")
    unique = []
    for u in urls:
        clean = u.strip(".,);]'\"")
        if clean not in unique:
            unique.append(clean)
        if len(unique) >= max_urls:
            break
    return unique


def queue_url_deep_scans(urls, background_tasks: BackgroundTasks, base_url: str, max_urls: int = 3):
    tasks = []
    for url in urls[:max_urls]:
        task_id = task_manager.create_task("url", url)
        background_tasks.add_task(
            analyze_url_background,
            task_id,
            url,
            True,
            True,
            True,
            base_url,
        )
        tasks.append({"url": url, "task_id": task_id})
    return tasks

async def analyze_url_background(task_id: str, url: str, use_external_apis: bool, enable_behavioral: bool, enable_live_capture: bool, base_url: str):
    """Background task for URL analysis with behavioral analysis"""
    try:
        await task_manager.update_task_progress(task_id, 5, "Starting analysis...")
        
        await task_manager.update_task_progress(task_id, 10, "Extracting URL features...")
        analyzer = BasicPhishingAnalyzer(url)
        features = await asyncio.to_thread(analyzer.analyze)
        
        if "error" in features:
            await task_manager.fail_task(task_id, features["error"])
            return
        
        await task_manager.update_task_progress(task_id, 25, "Feature extraction completed")
        
        behavioral_features = {}
        if enable_behavioral:
            await task_manager.update_task_progress(task_id, 30, "Running behavioral analysis...")
            behavioral_features = await behavioral_analyzer.analyze(url, enable_live_capture=enable_live_capture)
            behavioral_features = process_screenshot_url(behavioral_features, base_url)
            await task_manager.update_task_progress(task_id, 55, "Behavioral analysis completed")
        else:
            await task_manager.update_task_progress(task_id, 55, "Skipped behavioral analysis")
        
        external_results = {}
        if use_external_apis:
            await task_manager.update_task_progress(task_id, 60, "Querying external threat intelligence APIs...")
            external_results = await api_aggregator.check_url(url)
            await task_manager.update_task_progress(task_id, 80, "External API checks completed")
        else:
            await task_manager.update_task_progress(task_id, 80, "Skipped external APIs")
        
        await task_manager.update_task_progress(task_id, 85, "Running AI analysis...")
        
        combined_features = {**features, **behavioral_features}
        
        llm_result = await asyncio.to_thread(
            llm_analyzer.analyze_features,
            combined_features, 
            analysis_type="url",
            external_context=external_results
        )
        
        await task_manager.update_task_progress(task_id, 95, "Finalizing results...")
        
        result = {
            "analysis_type": "url",
            "input_data": url,
            "features": features,
            "behavioral_analysis": behavioral_features,
            "llm_analysis": llm_result,
            "external_apis": external_results,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        await task_manager.complete_task(task_id, result)
        
    except Exception as e:
        logger.exception("Background URL analysis failed", extra={"task_id": task_id, "url": url})
        await task_manager.fail_task(task_id, str(e))

@app.post("/analyze/url")
async def analyze_url(request: URLRequest, background_tasks: BackgroundTasks, fastapi_req: Request):
    """Analyze a URL for phishing indicators (with behavioral analysis)"""
    
    if request.async_mode:
        task_id = task_manager.create_task("url", request.url)
        
        background_tasks.add_task(
            analyze_url_background, 
            task_id, 
            request.url, 
            request.use_external_apis,
            request.enable_behavioral,
            request.enable_live_capture,
            str(fastapi_req.base_url)
        )
        
        return {
            "task_id": task_id,
            "status": "processing",
            "message": "Analysis started in background. Use /task/{task_id} to check progress."
        }
    else:
        start_time = time.time()
        
        try:
            url_str = request.url
            
            analyzer = BasicPhishingAnalyzer(url_str)
            features = await asyncio.to_thread(analyzer.analyze)
            
            if "error" in features:
                raise HTTPException(status_code=400, detail=features["error"])
            
            behavioral_features = {}
            if request.enable_behavioral:
                behavioral_features = await behavioral_analyzer.analyze(url_str, enable_live_capture=request.enable_live_capture)
                behavioral_features = process_screenshot_url(behavioral_features, str(fastapi_req.base_url))
            
            external_results = {}
            if request.use_external_apis:
                external_results = await api_aggregator.check_url(url_str)
            
            combined_features = {**features, **behavioral_features}
            llm_result = await asyncio.to_thread(
                llm_analyzer.analyze_features,
                combined_features, 
                analysis_type="url",
                external_context=external_results
            )
            
            processing_time = time.time() - start_time
            
            return {
                "analysis_type": "url",
                "input_data": url_str,
                "features": features,
                "behavioral_analysis": behavioral_features,
                "llm_analysis": llm_result,
                "external_apis": external_results,
                "processing_time": round(processing_time, 2),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Synchronous URL analysis failed", extra={"url": url_str})
            raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/qr")
async def analyze_qr(
    file: UploadFile = File(...), 
    use_external_apis: bool = Form(True),
    enable_behavioral: bool = Form(True),
    enable_live_capture: bool = Form(True),
    background_tasks: BackgroundTasks = None,
    fastapi_req: Request = None
):
    """
    Analyze QR code image. 
    Smart Routing: 
    - If URL found -> Triggers background URL analysis (same as URL tab).
    - If Text found -> Triggers immediate text analysis.
    """
    try:
        _validate_upload_size(file)
        file_ext = file.filename.split('.')[-1]
        temp_filename = f"qr_upload_{int(time.time())}.{file_ext}"
        temp_path = os.path.join("/tmp/phishing_screenshots", temp_filename)
        
        content = await file.read()
        if len(content) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=f"Upload exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES} bytes")
        with open(temp_path, "wb") as f:
            f.write(content)
            
        qr_results = await qr_analyzer.analyze_screenshot(temp_path, page_url=None)
        
        os.remove(temp_path) 
        
        if qr_results.get('qr_codes_found', 0) == 0:
            return {
                "analysis_type": "qr",
                "status": "failed",
                "error": "No QR code detected in the image"
            }

        first_code = qr_results['qr_codes'][0]
        data_content = first_code.get('data', '').strip()
        
        if first_code.get('type') == 'url' or data_content.startswith(('http', 'www')):
            
            target_url = data_content
            if not target_url.startswith('http'):
                target_url = f"https://{target_url}"
                
            task_id = task_manager.create_task("url", target_url)
            
            background_tasks.add_task(
                analyze_url_background, 
                task_id, 
                target_url, 
                use_external_apis,
                enable_behavioral,
                enable_live_capture,
                str(fastapi_req.base_url)
            )
            
            return {
                "analysis_type": "url_redirect", 
                "task_id": task_id,
                "detected_url": target_url,
                "message": f"QR Code contains URL: {target_url}. Starting deep analysis..."
            }
            
        else:
            features = {
                'text': data_content,
                'source': 'qr_scan',
                'qr_metadata': first_code
            }
            
            llm_result = await asyncio.to_thread(
                llm_analyzer.analyze_text, 
                data_content, 
                features
            )
            
            return {
                "analysis_type": "qr_text",
                "input_data": data_content,
                "features": features,
                "llm_analysis": llm_result,
                "processing_time": 0.5,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

    except Exception as e:
        logger.exception("QR analysis failed", extra={"file_name": file.filename if file else None})
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/screenshot/{filename}")
async def get_screenshot(filename: str):
    """Serve screenshot file"""
    filepath = _safe_join("/tmp/phishing_screenshots", filename)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    return FileResponse(filepath, media_type="image/png")

@app.get("/task/{task_id}")
async def get_task_status(task_id: str):
    """Get status of a background task"""
    task = task_manager.get_task(task_id)
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return task.to_dict()

@app.get("/task/{task_id}/stream")
async def stream_task_progress(task_id: str):
    """Stream task progress updates using Server-Sent Events"""
    
    async def event_generator():
        task = task_manager.get_task(task_id)
        
        if not task:
            yield f"data: {json.dumps({'error': 'Task not found'})}\n\n"
            return
        
        last_progress = -1
        
        while task.status in [TaskStatus.PENDING, TaskStatus.PROCESSING]:
            current_progress = task.progress
            
            if current_progress != last_progress:
                data = {
                    "task_id": task_id,
                    "status": task.status.value,
                    "progress": task.progress,
                    "current_step": task.current_step,
                    "steps_completed": task.steps_completed
                }
                yield f"data: {json.dumps(data)}\n\n"
                last_progress = current_progress
            
            await asyncio.sleep(0.5)  
        
        final_data = task.to_dict()
        yield f"data: {json.dumps(final_data)}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  
        }
    )

@app.post("/analyze/email")
async def analyze_email(file: UploadFile = File(...), background_tasks: BackgroundTasks = None, fastapi_req: Request = None):
    """Analyze an email file (.eml) for phishing indicators"""
    start_time = time.time()
    
    try:
        _validate_upload_size(file)
        if not file.filename.endswith('.eml'):
            raise HTTPException(status_code=400, detail="Only .eml files are supported")
        
        email_content = await file.read()
        if len(email_content) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=f"Upload exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES} bytes")
        
        analyzer = EmailPhishingAnalyzer(email_content)
        features = await asyncio.to_thread(analyzer.analyze)
        
        if "error" in features:
            raise HTTPException(status_code=400, detail=features["error"])
        
        llm_result = await asyncio.to_thread(
            llm_analyzer.analyze_features, 
            features, 
            analysis_type="email"
        )
        
        processing_time = time.time() - start_time

        deep_scan_tasks = []
        if background_tasks and fastapi_req:
            links = features.get("links", []) if isinstance(features, dict) else []
            deep_scan_tasks = queue_url_deep_scans(links, background_tasks, str(fastapi_req.base_url), max_urls=3)
        features["deep_scan_links_count"] = len(deep_scan_tasks)
        
        return {
            "analysis_type": "email",
            "input_data": file.filename,
            "features": features,
            "llm_analysis": llm_result,
            "external_apis": {},
            "url_deep_scans": deep_scan_tasks,
            "processing_time": round(processing_time, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Email analysis failed", extra={"file_name": file.filename if file else None})
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/text")
async def analyze_text(request: TextAnalysisRequest, background_tasks: BackgroundTasks, fastapi_req: Request):
    """Analyze raw text for phishing indicators"""
    start_time = time.time()
    
    try:
        text = request.text
        extracted_urls = extract_urls_from_text(text, max_urls=5)
        features = {
            'text': text[:2000],
            'length': len(text),
            'urgency_keywords': sum(1 for kw in ['urgent', 'immediate', 'verify', 'suspend', 'confirm'] 
                                   if kw.lower() in text.lower()),
            'financial_keywords': sum(1 for kw in ['bank', 'account', 'payment', 'credit'] 
                                     if kw.lower() in text.lower()),
            'has_links': bool(extracted_urls), 
            'link_count': len(extracted_urls),
            'extracted_urls': extracted_urls
        }
        
        llm_result = await asyncio.to_thread(llm_analyzer.analyze_text, text, features)
        
        processing_time = time.time() - start_time
        deep_scan_tasks = queue_url_deep_scans(features.get('extracted_urls', []), background_tasks, str(fastapi_req.base_url), max_urls=3)
        features['deep_scan_links_count'] = len(deep_scan_tasks)
        
        return {
            "analysis_type": "text",
            "input_data": text[:100] + "..." if len(text) > 100 else text,
            "features": features,
            "llm_analysis": llm_result,
            "external_apis": {},
            "url_deep_scans": deep_scan_tasks,
            "processing_time": round(processing_time, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Text analysis failed")
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/analyze/pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """Analyze a PCAP file for network forensics"""
    temp_path = None
    try:
        _validate_upload_size(file)
        if not file.filename.endswith(('.pcap', '.cap', '.pcapng')):
             raise HTTPException(status_code=400, detail="Only .pcap, .cap, or .pcapng files are supported")

        temp_dir = "/tmp/phishing_pcaps"
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, f"upload_{int(time.time())}_{file.filename}")
        
        total_written = 0
        with open(temp_path, "wb") as buffer:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(status_code=413, detail=f"Upload exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES} bytes")
                buffer.write(chunk)

        result = await pcap_analyzer.analyze_file(temp_path)

        if result.get("status") == "failed":
             raise HTTPException(status_code=500, detail=result.get("error"))

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("PCAP analysis failed", extra={"file_name": file.filename if file else None})
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning("Failed to remove temporary PCAP file", extra={"file_name": temp_path})

@app.get("/report/{task_id}/download")
async def download_report(task_id: str):
    task = task_manager.get_task(task_id)
    
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    status = task.status
    
    if hasattr(status, 'value'):
        status_str = str(status.value).lower()
    else:
        status_str = str(status).lower()

    if status_str != 'completed' and 'completed' not in status_str:
        raise HTTPException(status_code=404, detail=f"Analysis not complete (Status: {status})")

    result = getattr(task, 'result', None) or task.get('result')
    
    pdf_path = await report_gen.generate(task_id, result)
    
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Failed to generate report file")
        
    return FileResponse(
        pdf_path, 
        media_type='application/pdf', 
        filename=f"Forensic_Report_{task_id}.pdf"
    )

@app.get("/pcap/{filename}")
async def download_pcap(filename: str):
    """Download a specific PCAP file"""
    # Security:only serve from the temp directory and sanitize filename
    safe_filename = os.path.basename(filename)
    pcap_dir = "/tmp/phishing_pcaps"
    filepath = _safe_join(pcap_dir, safe_filename)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Capture file not found")
        
    return FileResponse(
        filepath, 
        media_type='application/vnd.tcpdump.pcap', 
        filename=safe_filename
    )

@app.exception_handler(422)
async def validation_exception_handler(request, exc):
    logger.warning("Validation error", extra={"url": str(request.url)})
    return JSONResponse(status_code=422, content={"detail": "Invalid input format. Please check your request."})


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    client_ip = request.client.host if request.client else "unknown"
    _enforce_rate_limit(client_ip)
    token = request_id_ctx.set(request_id)
    start = time.time()

    try:
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 2)
        logger.info("request.completed", extra={"url": str(request.url), "status_code": response.status_code, "duration_ms": duration_ms})
        response.headers["X-Request-ID"] = request_id
        return response
    except Exception:
        logger.exception("request.failed", extra={"url": str(request.url), "method": request.method})
        raise
    finally:
        request_id_ctx.reset(token)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
