"""
Advanced Search and Analytics Engine
====================================
Elasticsearch-powered search with analytics
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import re

logger = logging.getLogger(__name__)

try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    logger.warning("Elasticsearch not available - using fallback search")

class AdvancedSearchEngine:
    """Professional search engine with analytics"""
    
    def __init__(self):
        self.es_client = None
        self.index_name = "chainguard_evidence"
        
        if ELASTICSEARCH_AVAILABLE:
            self._setup_elasticsearch()
        
        self.search_history = []
        
    def _setup_elasticsearch(self):
        """Setup Elasticsearch connection"""
        try:
            es_url = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
            self.es_client = Elasticsearch([es_url])
            
            # Test connection
            if self.es_client.ping():
                self._create_index_if_not_exists()
                logger.info("Elasticsearch connected successfully")
            else:
                logger.warning("Elasticsearch connection failed")
                self.es_client = None
                
        except Exception as e:
            logger.error(f"Elasticsearch setup failed: {e}")
            self.es_client = None
    
    def _create_index_if_not_exists(self):
        """Create Elasticsearch index with proper mapping"""
        if not self.es_client.indices.exists(index=self.index_name):
            mapping = {
                "mappings": {
                    "properties": {
                        "evidence_id": {"type": "keyword"},
                        "filename": {"type": "text", "analyzer": "standard"},
                        "file_content": {"type": "text", "analyzer": "standard"},
                        "case_id": {"type": "keyword"},
                        "uploaded_by": {"type": "keyword"},
                        "uploaded_at": {"type": "date"},
                        "file_size": {"type": "long"},
                        "file_hash": {"type": "keyword"},
                        "risk_level": {"type": "keyword"},
                        "classification_level": {"type": "integer"},
                        "tags": {"type": "keyword"},
                        "metadata": {"type": "object"},
                        "ai_analysis": {"type": "object"},
                        "location": {"type": "geo_point"}
                    }
                }
            }
            
            self.es_client.indices.create(index=self.index_name, body=mapping)
            logger.info(f"Created Elasticsearch index: {self.index_name}")
    
    def index_evidence(self, evidence_data: Dict[str, Any]) -> bool:
        """Index evidence for searching"""
        try:
            if self.es_client:
                # Prepare document for indexing
                doc = self._prepare_document(evidence_data)
                
                response = self.es_client.index(
                    index=self.index_name,
                    id=evidence_data.get('evidence_id'),
                    body=doc
                )
                
                return response.get('result') == 'created' or response.get('result') == 'updated'
            
            return False
            
        except Exception as e:
            logger.error(f"Evidence indexing failed: {e}")
            return False
    
    def _prepare_document(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare document for Elasticsearch indexing"""
        doc = {
            'evidence_id': evidence_data.get('evidence_id'),
            'filename': evidence_data.get('filename'),
            'case_id': evidence_data.get('case_id'),
            'uploaded_by': evidence_data.get('uploaded_by'),
            'uploaded_at': evidence_data.get('uploaded_at'),
            'file_size': evidence_data.get('file_size'),
            'file_hash': evidence_data.get('file_hash_sha256'),
            'risk_level': evidence_data.get('risk_level'),
            'classification_level': evidence_data.get('classification_level'),
            'tags': evidence_data.get('tags', []),
            'metadata': evidence_data.get('metadata', {}),
            'ai_analysis': evidence_data.get('ai_analysis', {})
        }
        
        # Add searchable content extraction
        if 'file_content' in evidence_data:
            doc['file_content'] = evidence_data['file_content']
        
        return doc
    
    def advanced_search(self, query: str, filters: Dict[str, Any] = None, user_clearance: int = 5) -> Dict[str, Any]:
        """Perform advanced search with filters"""
        try:
            if self.es_client:
                return self._elasticsearch_search(query, filters, user_clearance)
            else:
                return self._fallback_search(query, filters, user_clearance)
                
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return {'hits': [], 'total': 0, 'aggregations': {}}
    
    def _elasticsearch_search(self, query: str, filters: Dict[str, Any], user_clearance: int) -> Dict[str, Any]:
        """Elasticsearch-powered search"""
        search_body = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"range": {"classification_level": {"lte": user_clearance}}}
                    ]
                }
            },
            "highlight": {
                "fields": {
                    "filename": {},
                    "file_content": {}
                }
            },
            "aggs": {
                "risk_levels": {"terms": {"field": "risk_level"}},
                "file_sizes": {"histogram": {"field": "file_size", "interval": 1000000}},
                "upload_timeline": {"date_histogram": {"field": "uploaded_at", "calendar_interval": "day"}},
                "top_uploaders": {"terms": {"field": "uploaded_by"}}
            },
            "sort": [{"uploaded_at": {"order": "desc"}}],
            "size": 50
        }
        
        # Add query conditions
        if query.strip():
            search_body["query"]["bool"]["must"].append({
                "multi_match": {
                    "query": query,
                    "fields": ["filename^3", "file_content^2", "case_id^2", "tags"],
                    "fuzziness": "AUTO"
                }
            })
        else:
            search_body["query"]["bool"]["must"].append({"match_all": {}})
        
        # Add filters
        if filters:
            if filters.get('risk_level'):
                search_body["query"]["bool"]["filter"].append(
                    {"term": {"risk_level": filters['risk_level']}}
                )
            
            if filters.get('case_id'):
                search_body["query"]["bool"]["filter"].append(
                    {"term": {"case_id": filters['case_id']}}
                )
            
            if filters.get('uploaded_by'):
                search_body["query"]["bool"]["filter"].append(
                    {"term": {"uploaded_by": filters['uploaded_by']}}
                )
            
            if filters.get('date_range'):
                search_body["query"]["bool"]["filter"].append(
                    {"range": {"uploaded_at": filters['date_range']}}
                )
        
        response = self.es_client.search(index=self.index_name, body=search_body)
        
        # Log search query
        self._log_search_query(query, filters, len(response['hits']['hits']))
        
        return {
            'hits': response['hits']['hits'],
            'total': response['hits']['total']['value'],
            'aggregations': response.get('aggregations', {}),
            'took': response['took']
        }
    
    def _fallback_search(self, query: str, filters: Dict[str, Any], user_clearance: int) -> Dict[str, Any]:
        """Fallback search implementation"""
        # Simple in-memory search - replace with database search
        results = []
        
        # This would typically query your database
        # For demo purposes, returning empty results
        
        self._log_search_query(query, filters, len(results))
        
        return {
            'hits': results,
            'total': len(results),
            'aggregations': {},
            'took': 0
        }
    
    def _log_search_query(self, query: str, filters: Dict[str, Any], results_count: int):
        """Log search queries for analytics"""
        search_entry = {
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'filters': filters or {},
            'results_count': results_count
        }
        
        self.search_history.append(search_entry)
        
        # Keep only last 1000 searches
        if len(self.search_history) > 1000:
            self.search_history.pop(0)
    
    def get_search_analytics(self) -> Dict[str, Any]:
        """Get search analytics and insights"""
        if not self.search_history:
            return {}
        
        total_searches = len(self.search_history)
        
        # Most common queries
        query_counts = {}
        for entry in self.search_history:
            query = entry['query'].lower().strip()
            if query:
                query_counts[query] = query_counts.get(query, 0) + 1
        
        top_queries = sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Average results per search
        total_results = sum(entry['results_count'] for entry in self.search_history)
        avg_results = total_results / total_searches if total_searches > 0 else 0
        
        # Search trends by hour
        hourly_counts = {}
        for entry in self.search_history:
            hour = datetime.fromisoformat(entry['timestamp']).hour
            hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        
        return {
            'total_searches': total_searches,
            'average_results_per_search': round(avg_results, 2),
            'top_queries': top_queries,
            'searches_by_hour': hourly_counts,
            'last_24h_searches': len([
                e for e in self.search_history 
                if datetime.fromisoformat(e['timestamp']) > datetime.now() - timedelta(days=1)
            ])
        }

# Global search engine instance
search_engine = AdvancedSearchEngine()
