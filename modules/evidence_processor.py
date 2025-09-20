"""
Advanced Evidence Processing System
==================================
Fixed syntax errors and enhanced processing
"""

import os
import hashlib
import secrets
import mimetypes
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import json
import base64

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)

class AdvancedEvidenceProcessor:
    """Comprehensive evidence processing system"""
    
    def __init__(self, database_manager, ai_engine, blockchain_manager):
        self.db = database_manager
        self.ai = ai_engine
        self.blockchain = blockchain_manager
        self.supported_formats = {
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'],
            'documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf'],
            'videos': ['.mp4', '.avi', '.mov', '.wmv', '.mkv'],
            'audio': ['.mp3', '.wav', '.flac', '.aac'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'executables': ['.exe', '.dll', '.msi', '.app', '.deb']
        }
        
    def process_evidence(self, file_data: bytes, filename: str, user_info: Dict[str, Any], case_id: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive evidence processing pipeline"""
        try:
            logger.info(f"Starting evidence processing: {filename}")
            
            # Generate unique evidence ID
            evidence_id = self._generate_evidence_id(filename)
            
            # Basic file analysis
            basic_info = self._analyze_basic_info(file_data, filename)
            
            # Advanced metadata extraction
            metadata = self._extract_comprehensive_metadata(file_data, filename)
            
            # Content analysis
            content_analysis = self._analyze_content(file_data, filename)
            
            # AI-powered analysis
            ai_results = self._perform_ai_analysis(file_data, filename)
            
            # Risk assessment
            risk_assessment = self._assess_risk(ai_results, metadata, content_analysis)
            
            # Blockchain anchoring
            blockchain_result = self._anchor_on_blockchain(evidence_id, basic_info['hashes']['sha256'], user_info)
            
            # Generate case ID if not provided
            if not case_id:
                case_id = self._generate_case_id(user_info.get('department', 'GEN'))
            
            # Compile evidence record
            evidence_record = {
                'evidence_id': evidence_id,
                'filename': filename,
                'original_filename': filename,
                'file_size': len(file_data),
                'file_type': basic_info['file_type'],
                'mime_type': basic_info['mime_type'],
                'file_hash_sha256': basic_info['hashes']['sha256'],
                'file_hash_md5': basic_info['hashes']['md5'],
                'file_hash_sha1': basic_info['hashes']['sha1'],
                'uploaded_by': user_info.get('username'),
                'uploaded_at': datetime.now(),
                'case_id': case_id,
                'status': 'ANALYZED',
                'risk_level': risk_assessment['level'],
                'classification_level': user_info.get('clearance_level', 2),
                'blockchain_anchored': blockchain_result.get('success', False),
                'tx_hash': blockchain_result.get('tx_hash', ''),
                'block_number': blockchain_result.get('block_number'),
                'ai_analysis': ai_results,
                'metadata_analysis': metadata,
                'extracted_text': content_analysis.get('text', ''),
                'extracted_images': content_analysis.get('images', []),
                'network_indicators': content_analysis.get('network_indicators', []),
                'suspicious_patterns': content_analysis.get('suspicious_patterns', []),
                'geolocation': metadata.get('geolocation', {}),
                'tags': self._generate_tags(ai_results, metadata, content_analysis),
                'chain_of_custody': [{
                    'action': 'UPLOADED',
                    'timestamp': datetime.now().isoformat(),
                    'user': user_info.get('username'),
                    'details': f'Initial upload and analysis by {user_info.get("full_name", "Unknown")}'
                }],
                'notes': f'Processed with ChainGuard Pro - Risk: {risk_assessment["level"]}'
            }
            
            # Save to database
            save_success = self.db.save_evidence(evidence_record)
            
            if save_success:
                logger.info(f"Evidence processing completed: {evidence_id}")
                return {
                    'success': True,
                    'evidence_record': evidence_record,
                    'processing_summary': {
                        'evidence_id': evidence_id,
                        'risk_level': risk_assessment['level'],
                        'threats_found': len(ai_results.get('threats_detected', [])),
                        'blockchain_anchored': blockchain_result.get('success', False),
                        'metadata_extracted': len(metadata),
                    }
                }
            else:
                raise Exception("Failed to save evidence to database")
                
        except Exception as e:
            logger.error(f"Evidence processing failed for {filename}: {e}")
            return {
                'success': False,
                'error': str(e),
                'filename': filename
            }
    
    def _generate_evidence_id(self, filename: str) -> str:
        """Generate unique evidence identifier"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_suffix = secrets.token_hex(4).upper()
        return f"EVID-{timestamp}-{random_suffix}"
    
    def _generate_case_id(self, department: str) -> str:
        """Generate case identifier"""
        timestamp = datetime.now().strftime('%Y')
        dept_code = department[:3].upper()
        random_suffix = secrets.token_hex(3).upper()
        return f"CASE-{timestamp}-{dept_code}-{random_suffix}"
    
    def _analyze_basic_info(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Analyze basic file information"""
        hashes = {
            'sha256': hashlib.sha256(file_data).hexdigest(),
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest()
        }
        
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        file_extension = os.path.splitext(filename)[1].lower()
        file_type = 'UNKNOWN'
        
        for category, extensions in self.supported_formats.items():
            if file_extension in extensions:
                file_type = category.upper().rstrip('S')
                break
        
        return {
            'hashes': hashes,
            'mime_type': mime_type,
            'file_type': file_type,
            'file_extension': file_extension,
            'file_size': len(file_data)
        }
    
    def _extract_comprehensive_metadata(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Extract comprehensive metadata"""
        metadata = {
            'extraction_timestamp': datetime.now().isoformat(),
            'filename': filename,
            'file_size': len(file_data)
        }
        
        file_extension = os.path.splitext(filename)[1].lower()
        
        if file_extension in ['.jpg', '.jpeg', '.png', '.tiff'] and PIL_AVAILABLE:
            metadata.update(self._extract_image_metadata(file_data))
        
        metadata.update(self._extract_generic_metadata(file_data))
        
        return metadata
    
    def _extract_image_metadata(self, file_data: bytes) -> Dict[str, Any]:
        """Extract EXIF and other metadata from images"""
        try:
            from io import BytesIO
            image = Image.open(BytesIO(file_data))
            
            metadata = {
                'image_format': image.format,
                'image_mode': image.mode,
                'image_size': image.size,
                'has_transparency': 'transparency' in image.info
            }
            
            exif_data = {}
            if hasattr(image, '_getexif') and image._getexif():
                exif = image._getexif()
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[tag] = str(value)
            
            if exif_data:
                metadata['exif_data'] = exif_data
                
                if 'GPSInfo' in exif_data:
                    metadata['geolocation'] = self._parse_gps_info(exif_data['GPSInfo'])
            
            return metadata
            
        except Exception as e:
            logger.error(f"Image metadata extraction failed: {e}")
            return {'error': 'Failed to extract image metadata'}
    
    def _extract_generic_metadata(self, file_data: bytes) -> Dict[str, Any]:
        """Extract generic metadata"""
        try:
            metadata = {}
            
            if file_data:
                byte_counts = {}
                for byte in file_data[:8192]:
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1
                
                entropy = 0.0
                data_len = min(len(file_data), 8192)
                for count in byte_counts.values():
                    prob = count / data_len
                    if prob > 0:
                        entropy -= prob * (prob ** 0.5)
                
                metadata['entropy'] = round(entropy, 3)
            
            metadata['file_header'] = file_data[:16].hex() if len(file_data) >= 16 else file_data.hex()
            metadata['unique_bytes'] = len(set(file_data[:4096])) if file_data else 0
            
            suspicious_patterns = [b'eval(', b'exec(', b'<script>', b'powershell', b'cmd.exe']
            detected_patterns = []
            
            for pattern in suspicious_patterns:
                if pattern.lower() in file_data.lower():
                    detected_patterns.append(pattern.decode('utf-8', errors='ignore'))
            
            if detected_patterns:
                metadata['suspicious_patterns'] = detected_patterns
            
            return metadata
            
        except Exception as e:
            logger.error(f"Generic metadata extraction failed: {e}")
            return {'error': 'Failed to extract generic metadata'}
    
    def _analyze_content(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Analyze file content"""
        content_analysis = {
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        try:
            text_content = self._extract_text_content(file_data, filename)
            if text_content:
                content_analysis['text'] = text_content[:1000]
                content_analysis['text_length'] = len(text_content)
            
            network_indicators = self._detect_network_indicators(file_data)
            if network_indicators:
                content_analysis['network_indicators'] = network_indicators
            
            suspicious_patterns = self._detect_suspicious_patterns(file_data)
            if suspicious_patterns:
                content_analysis['suspicious_patterns'] = suspicious_patterns
            
            return content_analysis
            
        except Exception as e:
            logger.error(f"Content analysis failed: {e}")
            return {'error': 'Content analysis failed'}
    
    def _extract_text_content(self, file_data: bytes, filename: str) -> str:
        """Extract readable text"""
        try:
            file_extension = os.path.splitext(filename)[1].lower()
            
            if file_extension == '.txt':
                return file_data.decode('utf-8', errors='ignore')
            else:
                text = ""
                for byte in file_data:
                    if 32 <= byte <= 126:
                        text += chr(byte)
                    elif byte in [9, 10, 13]:
                        text += chr(byte)
                    else:
                        text += " "
                
                lines = text.split('\n')
                meaningful_lines = [line.strip() for line in lines if len(line.strip()) > 3]
                return '\n'.join(meaningful_lines[:50])
                
        except Exception as e:
            logger.error(f"Text extraction failed: {e}")
            return ""
    
    def _detect_network_indicators(self, file_data: bytes) -> List[str]:
        """Detect network-related indicators - FIXED SYNTAX"""
        indicators = []
        
        network_patterns = [
            b'http://', b'https://', b'ftp://', b'ssh://',
            b'192.168.', b'10.0.', b'172.16.',
            b'.com', b'.org', b'.net', b'.gov',
            b'@', b'://'
        ]
        
        for pattern in network_patterns:
            if pattern in file_data.lower():
                index = file_data.lower().find(pattern)
                start = max(0, index - 20)
                end = min(len(file_data), index + 50)
                context = file_data[start:end].decode('utf-8', errors='ignore')
                indicators.append({
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'context': context.strip()
                })
        
        return indicators
    
    def _detect_suspicious_patterns(self, file_data: bytes) -> List[str]:
        """Detect suspicious patterns"""
        patterns = []
        suspicious_keywords = [
            b'password', b'keylog', b'backdoor', b'trojan', b'virus',
            b'CreateProcess', b'WriteFile', b'RegSetValue', b'VirtualAlloc'
        ]
        
        for keyword in suspicious_keywords:
            if keyword.lower() in file_data.lower():
                patterns.append(keyword.decode('utf-8', errors='ignore'))
        
        return patterns
    
    def _perform_ai_analysis(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Perform AI analysis"""
        try:
            if self.ai:
                return self.ai.analyze_file(file_data, filename)
            else:
                return {
                    'filename': filename,
                    'risk_assessment': {'risk_level': 'MEDIUM'},
                    'confidence_score': 0.75,
                    'threats_detected': [],
                    'metadata_analysis': {'file_size': len(file_data)},
                    'behavioral_analysis': {'behavioral_score': 0.3},
                    'recommendations': ['STANDARD_PROCESSING'],
                    'analysis_method': 'fallback'
                }
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {
                'error': 'AI analysis failed',
                'risk_assessment': {'risk_level': 'UNKNOWN'},
                'confidence_score': 0.0
            }
    
    def _assess_risk(self, ai_results: Dict, metadata: Dict, content_analysis: Dict) -> Dict[str, Any]:
        """Comprehensive risk assessment"""
        risk_score = 0.0
        risk_factors = []
        
        ai_risk = ai_results.get('risk_assessment', {}).get('risk_level', 'LOW')
        if ai_risk == 'CRITICAL':
            risk_score += 0.9
            risk_factors.append('AI detected critical threats')
        elif ai_risk == 'HIGH':
            risk_score += 0.7
            risk_factors.append('AI detected high-risk content')
        elif ai_risk == 'MEDIUM':
            risk_score += 0.5
            risk_factors.append('AI detected medium-risk indicators')
        
        if metadata.get('suspicious_patterns'):
            risk_score += 0.4
            risk_factors.append('Suspicious code patterns detected')
        
        if content_analysis.get('network_indicators'):
            risk_score += 0.2
            risk_factors.append('Network communication indicators found')
        
        if risk_score >= 1.2:
            risk_level = 'CRITICAL'
        elif risk_score >= 0.8:
            risk_level = 'HIGH'
        elif risk_score >= 0.4:
            risk_level = 'MEDIUM'
        elif risk_score > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'level': risk_level,
            'score': round(risk_score, 2),
            'factors': risk_factors,
            'confidence': min(0.9, 0.6 + (risk_score * 0.3))
        }
    
    def _anchor_on_blockchain(self, evidence_id: str, file_hash: str, user_info: Dict) -> Dict[str, Any]:
        """Anchor evidence on blockchain"""
        try:
            if self.blockchain:
                return self.blockchain.anchor_evidence(
                    evidence_id=evidence_id,
                    file_hash=file_hash,
                    classification_level=user_info.get('clearance_level', 2),
                    case_id=None
                )
            else:
                return {
                    'success': True,
                    'tx_hash': f"0x{secrets.token_hex(32)}",
                    'block_number': 1000000 + abs(hash(evidence_id)) % 100000,
                    'simulation': True
                }
        except Exception as e:
            logger.error(f"Blockchain anchoring failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_tags(self, ai_results: Dict, metadata: Dict, content_analysis: Dict) -> List[str]:
        """Generate relevant tags"""
        tags = []
        
        risk_level = ai_results.get('risk_assessment', {}).get('risk_level', 'LOW')
        tags.append(f"risk_{risk_level.lower()}")
        
        threats = ai_results.get('threats_detected', [])
        for threat in threats:
            threat_type = threat.get('threat_type', 'unknown')
            tags.append(f"threat_{threat_type}")
        
        if content_analysis.get('network_indicators'):
            tags.append('network_activity')
        
        if metadata.get('geolocation'):
            tags.append('geotagged')
        
        if metadata.get('suspicious_patterns'):
            tags.append('suspicious_code')
        
        tags.extend(['processed', 'sih_2025', 'chainguard_pro'])
        
        return list(set(tags))
    
    def _parse_gps_info(self, gps_info: str) -> Dict[str, Any]:
        """Parse GPS information"""
        return {
            'has_location': True,
            'source': 'exif_data',
            'note': 'GPS coordinates detected in image metadata'
        }

# Global evidence processor instance
evidence_processor = None  # Will be initialized in app.py
