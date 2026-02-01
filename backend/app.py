import time
import re
import json
import asyncio
import os
import logging
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, field_validator
from contextlib import asynccontextmanager
from analyzer import BasicPhishingAnalyzer
from email_analyzer import EmailPhishingAnalyzer
from llm_analyzer import GroqPhishingAnalyzer
from external_apis import ExternalAPIAggregator
from behavioral_analyzer import BehavioralAnalyzer 
from task_manager import task_manager, TaskStatus


@asynccontextmanager
async def lifespan(app: FastAPI):
    async def cleanup_tasks():
        while True:
            await asyncio.sleep(600)  # Every 10 minutes
            try:
                task_manager.cleanup_old_tasks(max_age_minutes=60)
            except Exception as e:
                logging.error(f"Error during background task cleanup: {e}")
    
    # Start the background cleanup task
    cleanup_task = asyncio.create_task(cleanup_tasks())
    
    yield  # The app stays here while running

    cleanup_task.cancel()  # Clean up the cleanup task
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

app = FastAPI(title="Phishing Detection API - Prototype", lifespan=lifespan)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str
    use_external_apis: bool = True
    async_mode: bool = True
    enable_behavioral: bool = True
    
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

# Background analysis function
async def analyze_url_background(task_id: str, url: str, use_external_apis: bool, enable_behavioral: bool, base_url: str):
    """Background task for URL analysis with behavioral analysis"""
    try:
        await task_manager.update_task_progress(task_id, 5, "Starting analysis...")
        
        # Step 1: Extract features (Run synchronous analyzer in thread pool to avoid blocking)
        await task_manager.update_task_progress(task_id, 10, "Extracting URL features...")
        analyzer = BasicPhishingAnalyzer(url)
        # Use asyncio.to_thread for blocking I/O calls
        features = await asyncio.to_thread(analyzer.analyze)
        
        if "error" in features:
            await task_manager.fail_task(task_id, features["error"])
            return
        
        await task_manager.update_task_progress(task_id, 25, "Feature extraction completed")
        
        # Step 2: Behavioral Analysis
        behavioral_features = {}
        if enable_behavioral:
            await task_manager.update_task_progress(task_id, 30, "Running behavioral analysis...")
            behavioral_features = await behavioral_analyzer.analyze(url)
            # Add screenshot URL
            behavioral_features = process_screenshot_url(behavioral_features, base_url)
            await task_manager.update_task_progress(task_id, 55, "Behavioral analysis completed")
        else:
            await task_manager.update_task_progress(task_id, 55, "Skipped behavioral analysis")
        
        # Step 3: External API checks
        external_results = {}
        if use_external_apis:
            await task_manager.update_task_progress(task_id, 60, "Querying external threat intelligence APIs...")
            external_results = await api_aggregator.check_url(url)
            await task_manager.update_task_progress(task_id, 80, "External API checks completed")
        else:
            await task_manager.update_task_progress(task_id, 80, "Skipped external APIs")
        
        # Step 4: LLM analysis
        await task_manager.update_task_progress(task_id, 85, "Running AI analysis...")
        
        # Combine all features for LLM
        combined_features = {**features, **behavioral_features}
        
        llm_result = await asyncio.to_thread(
            llm_analyzer.analyze_features,
            combined_features, 
            analysis_type="url",
            external_context=external_results
        )
        
        await task_manager.update_task_progress(task_id, 95, "Finalizing results...")
        
        # Prepare final result
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
        await task_manager.fail_task(task_id, str(e))

@app.post("/analyze/url")
async def analyze_url(request: URLRequest, background_tasks: BackgroundTasks, fastapi_req: Request):
    """Analyze a URL for phishing indicators (with behavioral analysis)"""
    
    if request.async_mode:
        # Create background task
        task_id = task_manager.create_task("url", request.url)
        
        # Start background processing
        background_tasks.add_task(
            analyze_url_background, 
            task_id, 
            request.url, 
            request.use_external_apis,
            request.enable_behavioral,
            str(fastapi_req.base_url)
        )
        
        return {
            "task_id": task_id,
            "status": "processing",
            "message": "Analysis started in background. Use /task/{task_id} to check progress."
        }
    else:
        # Synchronous processing
        start_time = time.time()
        
        try:
            url_str = request.url
            
            # Basic analysis (Run in thread pool)
            analyzer = BasicPhishingAnalyzer(url_str)
            features = await asyncio.to_thread(analyzer.analyze)
            
            if "error" in features:
                raise HTTPException(status_code=400, detail=features["error"])
            
            # Behavioral analysis
            behavioral_features = {}
            if request.enable_behavioral:
                behavioral_features = await behavioral_analyzer.analyze(url_str)
                behavioral_features = process_screenshot_url(behavioral_features, str(fastapi_req.base_url))
            
            # External APIs
            external_results = {}
            if request.use_external_apis:
                external_results = await api_aggregator.check_url(url_str)
            
            # LLM analysis
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
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/screenshot/{filename}")
async def get_screenshot(filename: str):
    """Serve screenshot file"""
    # Sanitize filename to prevent directory traversal
    filename = os.path.basename(filename)
    filepath = os.path.join("/tmp/phishing_screenshots", filename)
    
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
        
        # Stream updates until task is completed or failed
        while task.status in [TaskStatus.PENDING, TaskStatus.PROCESSING]:
            current_progress = task.progress
            
            # Only send update if progress changed
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
            
            await asyncio.sleep(0.5)  # Poll every 500ms
        
        # Send final status
        final_data = task.to_dict()
        yield f"data: {json.dumps(final_data)}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  # Disable nginx buffering
        }
    )

@app.post("/analyze/email")
async def analyze_email(file: UploadFile = File(...)):
    """Analyze an email file (.eml) for phishing indicators"""
    start_time = time.time()
    
    try:
        if not file.filename.endswith('.eml'):
            raise HTTPException(status_code=400, detail="Only .eml files are supported")
        
        email_content = await file.read()
        
        # BasicPhishingAnalyzer and EmailPhishingAnalyzer are synchronous, 
        # but email parsing is usually fast enough to run in main thread for small files.
        # For larger loads, we will need to wrap it into asyncio.to_thread as well, but for now I am keeping it simple.
        analyzer = EmailPhishingAnalyzer(email_content)
        features = await asyncio.to_thread(analyzer.analyze)
        
        if "error" in features:
            raise HTTPException(status_code=400, detail=features["error"])
        
        # Only passing features to LLM analyzer
        llm_result = await asyncio.to_thread(
            llm_analyzer.analyze_features, 
            features, 
            analysis_type="email"
        )
        
        processing_time = time.time() - start_time
        
        return {
            "analysis_type": "email",
            "input_data": file.filename,
            "features": features,
            "llm_analysis": llm_result,
            "external_apis": {},
            "processing_time": round(processing_time, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/text")
async def analyze_text(request: TextAnalysisRequest):
    """Analyze raw text for phishing indicators"""
    start_time = time.time()
    
    try:
        text = request.text
        
        # Extract basic features locally
        features = {
            'text': text[:2000],
            'length': len(text),
            'urgency_keywords': sum(1 for kw in ['urgent', 'immediate', 'verify', 'suspend', 'confirm'] 
                                   if kw.lower() in text.lower()),
            'financial_keywords': sum(1 for kw in ['bank', 'account', 'payment', 'credit'] 
                                     if kw.lower() in text.lower()),
            'has_links': bool(re.findall(r'http[s]?://\S+', text)), # doesn't capture all, but okay 
            'link_count': len(re.findall(r'http[s]?://\S+', text))
        }
        
        # Use LLM Analyzer method instead of ad-hoc helper
        llm_result = await asyncio.to_thread(llm_analyzer.analyze_text, text, features)
        
        processing_time = time.time() - start_time
        
        return {
            "analysis_type": "text",
            "input_data": text[:100] + "..." if len(text) > 100 else text,
            "features": features,
            "llm_analysis": llm_result,
            "external_apis": {},
            "processing_time": round(processing_time, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.exception_handler(422)
async def validation_exception_handler(request, exc):
    return {"detail": "Invalid input format. Please check your request."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)