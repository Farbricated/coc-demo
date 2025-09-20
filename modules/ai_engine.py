"""
Advanced AI Analysis Engine
===========================
Production-grade AI analysis with comprehensive threat detection
"""

import hashlib
import secrets
import math
import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    MINIMAL = "MINIMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FileType(Enum):
    EXECUTABLE = "EXECUTABLE"
    DOCUMENT = "DOCUMENT"
    IMAGE = "IMAGE"
    VIDEO = "VIDEO"
    AUDIO = "AUDIO"
    ARCHIVE = "ARCHIVE"
    DATABASE = "DATABASE"
    NETWORK_CAPTURE = "NETWORK_CAPTURE"
    SCRIPT = "SCRIPT"
    UNKNOWN = "UNKNOWN"

@dataclass
class ThreatSignature:
    name: str
    pattern: bytes
    threat_type: str
    severity: ThreatLevel
    description: str

class AIAnalysisEngine:
    """Professional AI analysis engine"""
    
    def __init__(self):
        self.version = "3.0.0"
        self.confidence_threshold = 0.85
        
        # Initialize threat signatures
        self._initialize_threat_signatures()
        
        # Initialize file type patterns
        self._initialize_file_patterns()
        
        logger.info(f"AI Analysis Engine v{self.version} initialized")
    
    def _initialize_threat_signatures(self):
        """Initialize comprehensive threat signature database"""
        self.threat_signatures = [
            # Executable signatures
            ThreatSignature("PE_EXECUTABLE", b'MZ', "malware", ThreatLevel.HIGH, "Windows PE executable detected"),
            ThreatSignature("ELF_EXECUTABLE", b'\x7fELF', "malware", ThreatLevel.HIGH, "Linux ELF executable detected"),
            ThreatSignature("MACH_O_EXECUTABLE", b'\xfe\xed\xfa\xce', "malware", ThreatLevel.HIGH, "macOS Mach-O executable detected"),
            
            # Archive threats
            ThreatSignature("ZIP_ARCHIVE", b'PK\x03\x04', "archive", ThreatLevel.MEDIUM, "ZIP archive detected"),
            ThreatSignature("RAR_ARCHIVE", b'Rar!', "archive", ThreatLevel.MEDIUM, "RAR archive detected"),
            
            # Script threats
            ThreatSignature("JAVASCRIPT_EVAL", b'eval(', "script_injection", ThreatLevel.HIGH, "JavaScript eval function"),
            ThreatSignature("POWERSHELL_SCRIPT", b'powershell', "script_execution", ThreatLevel.HIGH, "PowerShell script"),
            ThreatSignature("PYTHON_EXEC", b'exec(', "code_execution", ThreatLevel.MEDIUM, "Python exec function"),
            ThreatSignature("PHP_SCRIPT", b'<?php', "web_shell", ThreatLevel.HIGH, "PHP script detected"),
            
            # Suspicious strings
            ThreatSignature("PASSWORD_STRING", b'password', "credential_theft", ThreatLevel.MEDIUM, "Password string detected"),
            ThreatSignature("KEYLOGGER_STRING", b'keylog', "spyware", ThreatLevel.HIGH, "Keylogger indicator"),
            ThreatSignature("BACKDOOR_STRING", b'backdoor', "remote_access", ThreatLevel.CRITICAL, "Backdoor indicator"),
            ThreatSignature("RANSOMWARE_STRING", b'encrypt', "ransomware", ThreatLevel.CRITICAL, "Encryption activity"),
            
            # Network indicators
            ThreatSignature("HTTP_URL", b'http://', "network_communication", ThreatLevel.LOW, "HTTP URL detected"),
            ThreatSignature("HTTPS_URL", b'https://', "network_communication", ThreatLevel.LOW, "HTTPS URL detected"),
            ThreatSignature("FTP_URL", b'ftp://', "network_communication", ThreatLevel.MEDIUM, "FTP URL detected"),
            
            # System modification
            ThreatSignature("REGISTRY_MODIFY", b'HKEY_', "system_modification", ThreatLevel.MEDIUM, "Registry access detected"),
            ThreatSignature("SERVICE_CREATE", b'CreateService', "persistence", ThreatLevel.HIGH, "Service creation detected"),
        ]
    
    def _initialize_file_patterns(self):
        """Initialize file type detection patterns"""
        self.file_patterns = {
            # Executables
            b'MZ': FileType.EXECUTABLE,
            b'\x7fELF': FileType.EXECUTABLE,
            b'\xfe\xed\xfa\xce': FileType.EXECUTABLE,
            
            # Documents
            b'%PDF': FileType.DOCUMENT,
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': FileType.DOCUMENT,  # MS Office
            
            # Images
            b'\xff\xd8\xff': FileType.IMAGE,  # JPEG
            b'\x89PNG\r\n\x1a\n': FileType.IMAGE,  # PNG
            b'GIF87a': FileType.IMAGE,
            b'GIF89a': FileType.IMAGE,
            b'BM': FileType.IMAGE,  # BMP
            
            # Archives
            b'PK\x03\x04': FileType.ARCHIVE,  # ZIP
            b'Rar!': FileType.ARCHIVE,  # RAR
            b'\x1f\x8b': FileType.ARCHIVE,  # GZIP
            b'7z\xbc\xaf\x27\x1c': FileType.ARCHIVE,  # 7-Zip
            
            # Media
            b'RIFF': FileType.AUDIO,  # WAV
            b'ID3': FileType.AUDIO,  # MP3
            b'\x00\x00\x00\x18ftypmp4': FileType.VIDEO,  # MP4
            
            # Network captures
            b'\xd4\xc3\xb2\xa1': FileType.NETWORK_CAPTURE,  # PCAP
            b'\x0a\x0d\x0d\x0a': FileType.NETWORK_CAPTURE,  # PCAP-NG
            
            # Databases
            b'SQLite format 3': FileType.DATABASE,
        }
    
    def analyze_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Comprehensive file analysis"""
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting AI analysis: {filename}")
            
            # Validate input
            if len(file_data) == 0:
                return self._create_error_result(filename, "Empty file")
            
            if len(file_data) > 100 * 1024 * 1024:  # 100MB limit
                return self._create_error_result(filename, "File too large")
            
            # Core analysis components
            file_type = self._detect_file_type(file_data, filename)
            hashes = self._generate_hashes(file_data)
            threats = self._detect_threats(file_data)
            metadata = self._extract_metadata(file_data, filename)
            behavioral_analysis = self._analyze_behavior(file_data)
            risk_assessment = self._assess_risk(threats, file_type, len(file_data))
            
            # Calculate processing time
            processing_time = datetime.now() - start_time
            processing_time_ms = int(processing_time.total_seconds() * 1000)
            
            # Compile results
            analysis_results = {
                'filename': filename,
                'file_size': len(file_data),
                'file_type': file_type.value,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'processing_time_ms': processing_time_ms,
                'risk_assessment': {
                    'risk_level': risk_assessment['level'].value,
                    'risk_score': risk_assessment['score'],
                    'confidence': risk_assessment['confidence']
                },
                'confidence_score': self._calculate_confidence(threats, file_type),
                'threats_detected': threats,
                'metadata_analysis': metadata,
                'behavioral_analysis': behavioral_analysis,
                'recommendations': self._generate_recommendations(risk_assessment['level'], threats)
            }
            
            logger.info(f"AI analysis completed: {filename} - Risk: {risk_assessment['level'].value}")
            return analysis_results
            
        except Exception as e:
            logger.error(f"AI analysis error for {filename}: {e}")
            return self._create_error_result(filename, str(e))
    
    def _detect_file_type(self, file_data: bytes, filename: str) -> FileType:
        """Detect file type using magic numbers and filename"""
        # Check magic numbers first
        for pattern, file_type in self.file_patterns.items():
            if file_data.startswith(pattern):
                return file_type
        
        # Fallback to extension analysis
        if '.' in filename:
            extension = filename.split('.')[-1].lower()
            extension_map = {
                'exe': FileType.EXECUTABLE, 'dll': FileType.EXECUTABLE, 'msi': FileType.EXECUTABLE,
                'pdf': FileType.DOCUMENT, 'doc': FileType.DOCUMENT, 'docx': FileType.DOCUMENT,
                'jpg': FileType.IMAGE, 'jpeg': FileType.IMAGE, 'png': FileType.IMAGE, 'gif': FileType.IMAGE,
                'mp3': FileType.AUDIO, 'wav': FileType.AUDIO, 'mp4': FileType.VIDEO, 'avi': FileType.VIDEO,
                'zip': FileType.ARCHIVE, 'rar': FileType.ARCHIVE, '7z': FileType.ARCHIVE,
                'js': FileType.SCRIPT, 'py': FileType.SCRIPT, 'php': FileType.SCRIPT,
                'pcap': FileType.NETWORK_CAPTURE, 'db': FileType.DATABASE, 'sqlite': FileType.DATABASE
            }
            return extension_map.get(extension, FileType.UNKNOWN)
        
        return FileType.UNKNOWN
    
    def _generate_hashes(self, file_data: bytes) -> Dict[str, str]:
        """Generate comprehensive hash values"""
        return {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest(),
            'sha512': hashlib.sha512(file_data).hexdigest()
        }
    
    def _detect_threats(self, file_data: bytes) -> List[Dict[str, Any]]:
        """Comprehensive threat detection"""
        threats_found = []
        
        # Signature-based detection
        for signature in self.threat_signatures:
            if signature.pattern in file_data:
                threats_found.append({
                    'signature_name': signature.name,
                    'threat_type': signature.threat_type,
                    'severity': signature.severity.value,
                    'description': signature.description,
                    'confidence': self._calculate_signature_confidence(signature, file_data),
                    'offset': file_data.find(signature.pattern),
                    'detection_method': 'signature_based'
                })
        
        # Entropy-based analysis
        entropy_threats = self._detect_entropy_anomalies(file_data)
        threats_found.extend(entropy_threats)
        
        # Pattern-based detection
        pattern_threats = self._detect_suspicious_patterns(file_data)
        threats_found.extend(pattern_threats)
        
        return threats_found
    
    def _calculate_signature_confidence(self, signature: ThreatSignature, file_data: bytes) -> float:
        """Calculate confidence for signature detection"""
        base_confidence = 0.7
        
        # Multiple occurrences increase confidence
        pattern_count = file_data.count(signature.pattern)
        if pattern_count > 1:
            base_confidence += min(0.2, 0.05 * pattern_count)
        
        # Position affects confidence
        first_occurrence = file_data.find(signature.pattern)
        if first_occurrence < 1024:  # Found in first 1KB
            base_confidence += 0.1
        
        return min(base_confidence, 0.95)
    
    def _detect_entropy_anomalies(self, file_data: bytes) -> List[Dict[str, Any]]:
        """Detect entropy-based anomalies"""
        anomalies = []
        
        try:
            # Calculate overall entropy
            entropy = self._calculate_entropy(file_data[:8192])  # First 8KB
            
            if entropy > 7.5:  # High entropy threshold
                anomalies.append({
                    'signature_name': 'HIGH_ENTROPY_CONTENT',
                    'threat_type': 'encrypted_or_packed',
                    'severity': ThreatLevel.MEDIUM.value,
                    'description': f'High entropy content detected ({entropy:.2f})',
                    'confidence': min((entropy - 7.0) / 1.0, 0.9),
                    'detection_method': 'entropy_analysis',
                    'entropy_value': entropy
                })
            
        except Exception as e:
            logger.error(f"Entropy analysis failed: {e}")
        
        return anomalies
    
    def _detect_suspicious_patterns(self, file_data: bytes) -> List[Dict[str, Any]]:
        """Detect suspicious behavioral patterns"""
        patterns = []
        
        suspicious_apis = [
            (b'CreateProcess', 'process_creation'),
            (b'WriteFile', 'file_modification'),
            (b'RegSetValue', 'registry_modification'),
            (b'VirtualAlloc', 'memory_allocation'),
            (b'GetProcAddress', 'api_resolution'),
            (b'LoadLibrary', 'library_loading')
        ]
        
        for pattern, behavior_type in suspicious_apis:
            if pattern.lower() in file_data.lower():
                patterns.append({
                    'signature_name': f'SUSPICIOUS_{behavior_type.upper()}',
                    'threat_type': behavior_type,
                    'severity': ThreatLevel.MEDIUM.value,
                    'description': f'Suspicious {behavior_type} pattern detected',
                    'confidence': 0.6,
                    'detection_method': 'pattern_analysis'
                })
        
        return patterns
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        if NUMPY_AVAILABLE:
            byte_counts = np.bincount(list(data), minlength=256)
            probabilities = byte_counts / len(data)
            probabilities = probabilities[probabilities > 0]
            return float(-np.sum(probabilities * np.log2(probabilities)))
        else:
            # Fallback calculation
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            entropy = 0.0
            for count in byte_counts.values():
                prob = count / len(data)
                if prob > 0:
                    entropy -= prob * math.log2(prob)
            
            return entropy
    
    def _extract_metadata(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Extract comprehensive metadata"""
        metadata = {
            'filename': filename,
            'file_size': len(file_data),
            'file_extension': filename.split('.')[-1].lower() if '.' in filename else '',
            'entropy': self._calculate_entropy(file_data[:4096]),
            'unique_bytes': len(set(file_data[:4096])) if file_data else 0,
            'printable_ratio': self._calculate_printable_ratio(file_data[:4096]),
            'creation_timestamp': datetime.utcnow().isoformat()
        }
        
        # Add MIME type if magic is available
        if MAGIC_AVAILABLE:
            try:
                metadata['mime_type'] = magic.from_buffer(file_data, mime=True)
            except Exception:
                metadata['mime_type'] = 'unknown'
        
        return metadata
    
    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable ASCII characters"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        return printable_count / len(data)
    
    def _analyze_behavior(self, file_data: bytes) -> Dict[str, Any]:
        """Analyze potential behavioral indicators"""
        return {
            'suspicious_strings': self._extract_suspicious_strings(file_data),
            'network_indicators': self._detect_network_indicators(file_data),
            'behavioral_score': self._calculate_behavioral_score(file_data)
        }
    
    def _extract_suspicious_strings(self, file_data: bytes) -> List[str]:
        """Extract suspicious strings from file"""
        suspicious_keywords = [b'password', b'keylog', b'backdoor', b'trojan', b'virus']
        found_strings = []
        
        for keyword in suspicious_keywords:
            if keyword in file_data.lower():
                found_strings.append(keyword.decode('utf-8', errors='ignore'))
        
        return found_strings
    
    def _detect_network_indicators(self, file_data: bytes) -> List[str]:
        """Detect network communication indicators"""
        indicators = []
        network_patterns = [b'http://', b'https://', b'ftp://', b'smtp://', b'.onion']
        
        for pattern in network_patterns:
            if pattern in file_data.lower():
                indicators.append(pattern.decode('utf-8', errors='ignore'))
        
        return indicators
    
    def _calculate_behavioral_score(self, file_data: bytes) -> float:
        """Calculate behavioral risk score"""
        score = 0.0
        
        # Check for suspicious API calls
        suspicious_apis = [b'CreateProcess', b'WriteFile', b'RegSetValue', b'VirtualAlloc']
        for api in suspicious_apis:
            if api in file_data:
                score += 0.2
        
        # Check for network indicators
        network_patterns = [b'http://', b'https://', b'socket', b'connect']
        for pattern in network_patterns:
            if pattern in file_data.lower():
                score += 0.1
        
        return min(score, 1.0)
    
    def _assess_risk(self, threats: List[Dict], file_type: FileType, file_size: int) -> Dict[str, Any]:
        """Assess overall risk level"""
        total_score = 0.0
        
        # Threat-based scoring
        for threat in threats:
            severity = threat.get('severity', 'LOW')
            if severity == 'CRITICAL':
                total_score += 0.9
            elif severity == 'HIGH':
                total_score += 0.7
            elif severity == 'MEDIUM':
                total_score += 0.5
            elif severity == 'LOW':
                total_score += 0.3
            else:
                total_score += 0.1
        
        # File type risk adjustment
        if file_type in [FileType.EXECUTABLE, FileType.SCRIPT]:
            total_score += 0.3
        elif file_type == FileType.UNKNOWN:
            total_score += 0.2
        
        # File size considerations
        if file_size > 50 * 1024 * 1024:  # > 50MB
            total_score += 0.1
        
        # Determine risk level
        if total_score >= 1.5:
            risk_level = ThreatLevel.CRITICAL
        elif total_score >= 1.0:
            risk_level = ThreatLevel.HIGH
        elif total_score >= 0.5:
            risk_level = ThreatLevel.MEDIUM
        elif total_score > 0.0:
            risk_level = ThreatLevel.LOW
        else:
            risk_level = ThreatLevel.MINIMAL
        
        # Calculate confidence
        confidence = min(0.8 + (len(threats) * 0.1), 0.95)
        
        return {
            'level': risk_level,
            'score': total_score,
            'confidence': confidence
        }
    
    def _calculate_confidence(self, threats: List[Dict], file_type: FileType) -> float:
        """Calculate overall analysis confidence"""
        base_confidence = 0.75
        
        # Increase confidence based on detections
        if threats:
            base_confidence += min(0.2, len(threats) * 0.05)
        
        # File type recognition increases confidence
        if file_type != FileType.UNKNOWN:
            base_confidence += 0.05
        
        return min(base_confidence, 0.98)
    
    def _generate_recommendations(self, risk_level: ThreatLevel, threats: List[Dict]) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        if risk_level == ThreatLevel.CRITICAL:
            recommendations.extend([
                'ISOLATE_IMMEDIATELY',
                'NOTIFY_SECURITY_TEAM',
                'PERFORM_FORENSIC_ANALYSIS',
                'SCAN_NETWORK_FOR_INDICATORS'
            ])
        elif risk_level == ThreatLevel.HIGH:
            recommendations.extend([
                'QUARANTINE_FILE',
                'DETAILED_ANALYSIS_REQUIRED',
                'MONITOR_SYSTEM_ACTIVITY'
            ])
        elif risk_level == ThreatLevel.MEDIUM:
            recommendations.extend([
                'ADDITIONAL_SCANNING_RECOMMENDED',
                'VERIFY_FILE_SOURCE'
            ])
        elif risk_level == ThreatLevel.LOW:
            recommendations.append('STANDARD_PROCESSING_APPROVED')
        else:
            recommendations.append('FILE_APPEARS_SAFE')
        
        # Add specific recommendations based on threat types
        threat_types = [threat.get('threat_type', '') for threat in threats]
        if 'malware' in threat_types:
            recommendations.append('ANTIVIRUS_SCAN_REQUIRED')
        if 'network_communication' in threat_types:
            recommendations.append('MONITOR_NETWORK_TRAFFIC')
        if 'script_execution' in threat_types:
            recommendations.append('DISABLE_SCRIPT_EXECUTION')
        
        return list(set(recommendations))  # Remove duplicates
    
    def _create_error_result(self, filename: str, error_message: str) -> Dict[str, Any]:
        """Create standardized error result"""
        return {
            'filename': filename,
            'error': error_message,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'risk_assessment': {'risk_level': 'UNKNOWN'},
            'confidence_score': 0.0,
            'threats_detected': [],
            'metadata_analysis': {},
            'behavioral_analysis': {},
            'recommendations': ['MANUAL_ANALYSIS_REQUIRED']
        }

# Global AI engine instance
ai_engine = AIAnalysisEngine()
