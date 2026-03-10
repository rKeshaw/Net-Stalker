import uuid
import asyncio
from typing import Dict, Optional, Any
from datetime import datetime
from enum import Enum

class TaskStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class AnalysisTask:
    def __init__(self, task_id: str, analysis_type: str, input_data: str):
        self.task_id = task_id
        self.analysis_type = analysis_type
        self.input_data = input_data
        self.status = TaskStatus.PENDING
        self.progress = 0
        self.current_step = "Initializing..."
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.completed_at = None
        self.steps_completed = []
        
    def update_progress(self, progress: int, step: str):
        """Update task progress"""
        self.progress = min(progress, 100)
        self.current_step = step
        if step not in self.steps_completed:
            self.steps_completed.append(step)
    
    def mark_completed(self, result: Any):
        """Mark task as completed"""
        self.status = TaskStatus.COMPLETED
        self.progress = 100
        self.current_step = "Completed"
        self.result = result
        self.completed_at = datetime.now()
    
    def mark_failed(self, error: str):
        """Mark task as failed"""
        self.status = TaskStatus.FAILED
        self.error = error
        self.completed_at = datetime.now()
    
    def to_dict(self) -> Dict:
        """Convert task to dictionary"""
        return {
            "task_id": self.task_id,
            "analysis_type": self.analysis_type,
            "status": self.status.value,
            "progress": self.progress,
            "current_step": self.current_step,
            "steps_completed": self.steps_completed,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }

class TaskManager:
    def __init__(self, max_tasks: int = 2000):
        self.tasks: Dict[str, AnalysisTask] = {}
        self._lock = asyncio.Lock()
        self.max_tasks = max_tasks
    
    def create_task(self, analysis_type: str, input_data: str) -> str:
        """Create a new analysis task"""
        if len(self.tasks) >= self.max_tasks:
            self._evict_oldest_task()
        task_id = str(uuid.uuid4())
        task = AnalysisTask(task_id, analysis_type, input_data)
        self.tasks[task_id] = task
        return task_id
    
    def _evict_oldest_task(self):
        """Evict the oldest task to enforce an upper bound on in-memory task count."""
        if not self.tasks:
            return
        oldest_task_id = min(self.tasks.items(), key=lambda item: item[1].created_at)[0]
        del self.tasks[oldest_task_id]
    
    def get_task(self, task_id: str) -> Optional[AnalysisTask]:
        """Get task by ID"""
        return self.tasks.get(str(task_id))
    
    async def update_task_progress(self, task_id: str, progress: int, step: str):
        """Update task progress thread-safe"""
        async with self._lock:
            task = self.get_task(str(task_id))
            if task:
                task.update_progress(progress, step)
    
    async def complete_task(self, task_id: str, result: Any):
        """Mark task as completed thread-safe"""
        async with self._lock:
            task = self.get_task(str(task_id))
            if task:
                task.mark_completed(result)
    
    async def fail_task(self, task_id: str, error: str):
        """Mark task as failed thread-safe"""
        async with self._lock:
            task = self.get_task(str(task_id))
            if task:
                task.mark_failed(error)
    
    def cleanup_old_tasks(self, max_age_minutes: int = 60):
        """Remove tasks older than max_age_minutes"""
        now = datetime.now()
        to_remove = []
        
        for task_id, task in self.tasks.items():
            reference_time = task.completed_at or task.created_at
            age = (now - reference_time).total_seconds() / 60
            if age > max_age_minutes:
                to_remove.append(task_id)
        
        for task_id in to_remove:
            del self.tasks[task_id]

task_manager = TaskManager()
