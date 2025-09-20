"""
Real-time System Monitoring
===========================
Live monitoring and alerting system
"""

import psutil
import threading
import time
from datetime import datetime
from typing import Dict, List, Callable
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass
class SystemMetric:
    name: str
    value: float
    unit: str
    timestamp: datetime
    threshold: float = None
    alert_level: AlertLevel = AlertLevel.INFO

class SystemMonitor:
    """Professional system monitoring with real-time alerts"""
    
    def __init__(self, update_interval: int = 30):
        self.update_interval = update_interval
        self.metrics_history: List[Dict] = []
        self.alert_callbacks: List[Callable] = []
        self.monitoring_active = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start continuous monitoring"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join()
        logger.info("System monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                metrics = self._collect_metrics()
                self._process_metrics(metrics)
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(self.update_interval)
    
    def _collect_metrics(self) -> List[SystemMetric]:
        """Collect comprehensive system metrics"""
        metrics = []
        timestamp = datetime.now()
        
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        metrics.append(SystemMetric("cpu_usage", cpu_percent, "%", timestamp, threshold=80.0))
        
        # Memory metrics
        memory = psutil.virtual_memory()
        metrics.append(SystemMetric("memory_usage", memory.percent, "%", timestamp, threshold=85.0))
        metrics.append(SystemMetric("memory_available", memory.available / (1024**3), "GB", timestamp))
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        metrics.append(SystemMetric("disk_usage", disk_percent, "%", timestamp, threshold=90.0))
        
        # Network metrics
        network = psutil.net_io_counters()
        metrics.append(SystemMetric("network_bytes_sent", network.bytes_sent, "bytes", timestamp))
        metrics.append(SystemMetric("network_bytes_recv", network.bytes_recv, "bytes", timestamp))
        
        # Process metrics
        process_count = len(psutil.pids())
        metrics.append(SystemMetric("process_count", process_count, "count", timestamp))
        
        # Application-specific metrics
        metrics.extend(self._collect_app_metrics(timestamp))
        
        return metrics
    
    def _collect_app_metrics(self, timestamp: datetime) -> List[SystemMetric]:
        """Collect application-specific metrics"""
        metrics = []
        
        try:
            # Database connections (example)
            metrics.append(SystemMetric("active_db_connections", 5, "count", timestamp))
            
            # Evidence processing queue
            metrics.append(SystemMetric("evidence_queue_size", 0, "count", timestamp))
            
            # Active user sessions
            metrics.append(SystemMetric("active_sessions", 3, "count", timestamp))
            
        except Exception as e:
            logger.error(f"App metrics collection failed: {e}")
        
        return metrics
    
    def _process_metrics(self, metrics: List[SystemMetric]):
        """Process metrics and generate alerts"""
        current_snapshot = {
            'timestamp': datetime.now().isoformat(),
            'metrics': {}
        }
        
        for metric in metrics:
            current_snapshot['metrics'][metric.name] = {
                'value': metric.value,
                'unit': metric.unit,
                'timestamp': metric.timestamp.isoformat()
            }
            
            # Check thresholds and generate alerts
            if metric.threshold and metric.value > metric.threshold:
                self._trigger_alert(metric, AlertLevel.WARNING)
        
        # Store in history (keep last 1000 snapshots)
        self.metrics_history.append(current_snapshot)
        if len(self.metrics_history) > 1000:
            self.metrics_history.pop(0)
    
    def _trigger_alert(self, metric: SystemMetric, level: AlertLevel):
        """Trigger system alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'level': level.value,
            'metric': metric.name,
            'value': metric.value,
            'threshold': metric.threshold,
            'message': f"{metric.name} exceeded threshold: {metric.value}{metric.unit} > {metric.threshold}{metric.unit}"
        }
        
        logger.warning(f"ALERT: {alert['message']}")
        
        # Call registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def get_current_metrics(self) -> Dict:
        """Get current system metrics"""
        if self.metrics_history:
            return self.metrics_history[-1]
        return {}
    
    def get_metrics_history(self, hours: int = 24) -> List[Dict]:
        """Get metrics history for specified hours"""
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        
        filtered_history = []
        for snapshot in self.metrics_history:
            snapshot_time = datetime.fromisoformat(snapshot['timestamp']).timestamp()
            if snapshot_time >= cutoff_time:
                filtered_history.append(snapshot)
        
        return filtered_history
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for alerts"""
        self.alert_callbacks.append(callback)

# Global monitor instance
system_monitor = SystemMonitor()
