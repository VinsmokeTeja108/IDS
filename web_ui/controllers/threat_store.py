"""
ThreatStore for in-memory threat storage.

This module provides an in-memory storage solution for detected threats
with filtering, retrieval, and automatic cleanup capabilities.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import uuid


class ThreatStore:
    """
    In-memory store for detected threats with persistence and filtering.
    
    The ThreatStore maintains a collection of detected threats, provides
    filtering capabilities by type, severity, and time range, and automatically
    manages storage by keeping only the most recent threats.
    """
    
    def __init__(self, max_threats: int = 1000):
        """
        Initialize the threat store.
        
        Args:
            max_threats: Maximum number of threats to keep in memory.
                        Older threats are automatically removed when this
                        limit is exceeded. Default is 1000.
        """
        self.threats: List[Dict[str, Any]] = []
        self.max_threats = max_threats
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"ThreatStore initialized with max_threats={max_threats}")
    
    def add_threat(self, threat_analysis) -> str:
        """
        Store a detected threat in memory.
        
        This method converts a ThreatAnalysis object to a dictionary format
        suitable for storage and retrieval, assigns a unique ID, and adds it
        to the threat collection. Automatically triggers cleanup if the maximum
        threat count is exceeded.
        
        Args:
            threat_analysis: ThreatAnalysis object containing threat details
        
        Returns:
            str: Unique ID assigned to the stored threat
        
        Example:
            threat_id = threat_store.add_threat(threat_analysis)
            print(f"Stored threat with ID: {threat_id}")
        """
        try:
            # Generate unique ID for the threat
            threat_id = str(uuid.uuid4())
            
            # Extract threat event data
            threat_event = threat_analysis.threat_event
            
            # Convert ThreatAnalysis to dictionary format
            threat_dict = {
                'id': threat_id,
                'timestamp': threat_event.timestamp.isoformat() if isinstance(threat_event.timestamp, datetime) else str(threat_event.timestamp),
                'type': threat_event.threat_type.value if hasattr(threat_event.threat_type, 'value') else str(threat_event.threat_type),
                'severity': threat_analysis.severity.value if hasattr(threat_analysis.severity, 'value') else str(threat_analysis.severity),
                'source_ip': threat_event.source_ip,
                'destination_ip': threat_event.destination_ip,
                'protocol': threat_event.protocol,
                'classification': threat_analysis.classification,
                'description': threat_analysis.description,
                'recommendations': threat_analysis.recommendations,
                'justification': threat_analysis.justification,
                'raw_data': threat_event.raw_data
            }
            
            # Add to the beginning of the list (most recent first)
            self.threats.insert(0, threat_dict)
            
            self.logger.info(f"Added threat {threat_id}: {threat_dict['type']} from {threat_dict['source_ip']}")
            
            # Cleanup old threats if necessary
            if len(self.threats) > self.max_threats:
                self.clear_old_threats()
            
            return threat_id
            
        except Exception as e:
            self.logger.error(f"Error adding threat to store: {e}")
            raise
    
    def get_threats(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Retrieve threats with optional filtering.
        
        Supports filtering by threat type, severity level, time range, and limit.
        Multiple filters can be combined. If no filters are provided, returns
        all threats.
        
        Args:
            filters: Optional dictionary containing filter criteria:
                - 'type': str or List[str] - Filter by threat type(s)
                - 'severity': str or List[str] - Filter by severity level(s)
                - 'start_time': str (ISO format) - Filter threats after this time
                - 'end_time': str (ISO format) - Filter threats before this time
                - 'limit': int - Maximum number of threats to return
                - 'source_ip': str - Filter by source IP address
        
        Returns:
            List[Dict[str, Any]]: List of threat dictionaries matching the filters
        
        Example:
            # Get all high severity threats
            threats = threat_store.get_threats({'severity': 'high'})
            
            # Get port scans from last hour
            threats = threat_store.get_threats({
                'type': 'port_scan',
                'start_time': (datetime.now() - timedelta(hours=1)).isoformat()
            })
        """
        if not filters:
            return self.threats.copy()
        
        filtered_threats = self.threats.copy()
        
        try:
            # Filter by threat type
            if 'type' in filters:
                threat_types = filters['type'] if isinstance(filters['type'], list) else [filters['type']]
                filtered_threats = [t for t in filtered_threats if t['type'] in threat_types]
            
            # Filter by severity
            if 'severity' in filters:
                severities = filters['severity'] if isinstance(filters['severity'], list) else [filters['severity']]
                filtered_threats = [t for t in filtered_threats if t['severity'] in severities]
            
            # Filter by source IP
            if 'source_ip' in filters:
                source_ip = filters['source_ip']
                filtered_threats = [t for t in filtered_threats if t['source_ip'] == source_ip]
            
            # Filter by time range
            if 'start_time' in filters:
                start_time = datetime.fromisoformat(filters['start_time'].replace('Z', '+00:00'))
                filtered_threats = [
                    t for t in filtered_threats 
                    if datetime.fromisoformat(t['timestamp'].replace('Z', '+00:00')) >= start_time
                ]
            
            if 'end_time' in filters:
                end_time = datetime.fromisoformat(filters['end_time'].replace('Z', '+00:00'))
                filtered_threats = [
                    t for t in filtered_threats 
                    if datetime.fromisoformat(t['timestamp'].replace('Z', '+00:00')) <= end_time
                ]
            
            # Apply limit
            if 'limit' in filters:
                limit = int(filters['limit'])
                filtered_threats = filtered_threats[:limit]
            
            self.logger.debug(f"Retrieved {len(filtered_threats)} threats with filters: {filters}")
            return filtered_threats
            
        except Exception as e:
            self.logger.error(f"Error filtering threats: {e}")
            return []
    
    def get_threat_by_id(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve detailed information for a specific threat by ID.
        
        Args:
            threat_id: Unique identifier of the threat to retrieve
        
        Returns:
            Optional[Dict[str, Any]]: Threat dictionary if found, None otherwise
        
        Example:
            threat = threat_store.get_threat_by_id('123e4567-e89b-12d3-a456-426614174000')
            if threat:
                print(f"Found threat: {threat['type']}")
        """
        try:
            for threat in self.threats:
                if threat['id'] == threat_id:
                    self.logger.debug(f"Retrieved threat by ID: {threat_id}")
                    return threat.copy()
            
            self.logger.warning(f"Threat not found: {threat_id}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error retrieving threat by ID {threat_id}: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Calculate and return threat analytics and statistics.
        
        Provides comprehensive statistics including total threat count,
        distribution by severity and type, top attacking IPs, and recent
        threat activity.
        
        Returns:
            Dict[str, Any]: Dictionary containing:
                - 'total_threats': Total number of stored threats
                - 'by_severity': Count of threats by severity level
                - 'by_type': Count of threats by threat type
                - 'top_attackers': List of top attacking source IPs with counts
                - 'recent_count': Number of threats in the last hour
                - 'last_threat_time': Timestamp of most recent threat
        
        Example:
            stats = threat_store.get_statistics()
            print(f"Total threats: {stats['total_threats']}")
            print(f"Critical threats: {stats['by_severity']['critical']}")
        """
        try:
            # Initialize statistics structure
            stats = {
                'total_threats': len(self.threats),
                'by_severity': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                },
                'by_type': defaultdict(int),
                'top_attackers': [],
                'recent_count': 0,
                'last_threat_time': None
            }
            
            if not self.threats:
                return stats
            
            # Count by severity and type
            attacker_counts = defaultdict(int)
            one_hour_ago = datetime.now() - timedelta(hours=1)
            
            for threat in self.threats:
                # Count by severity
                severity = threat['severity']
                if severity in stats['by_severity']:
                    stats['by_severity'][severity] += 1
                
                # Count by type
                threat_type = threat['type']
                stats['by_type'][threat_type] += 1
                
                # Count attackers
                source_ip = threat['source_ip']
                attacker_counts[source_ip] += 1
                
                # Count recent threats (last hour)
                try:
                    threat_time = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
                    if threat_time >= one_hour_ago:
                        stats['recent_count'] += 1
                except Exception:
                    pass
            
            # Convert by_type defaultdict to regular dict
            stats['by_type'] = dict(stats['by_type'])
            
            # Get top 10 attackers
            stats['top_attackers'] = [
                {'ip': ip, 'count': count}
                for ip, count in sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
            
            # Get last threat time
            if self.threats:
                stats['last_threat_time'] = self.threats[0]['timestamp']
            
            self.logger.debug(f"Generated statistics: {stats['total_threats']} total threats")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error generating statistics: {e}")
            return {
                'total_threats': 0,
                'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'by_type': {},
                'top_attackers': [],
                'recent_count': 0,
                'last_threat_time': None
            }
    
    def clear_old_threats(self) -> int:
        """
        Remove old threats to maintain the maximum threat limit.
        
        This method is automatically called when adding threats exceeds
        the max_threats limit. It removes the oldest threats to keep
        the collection size within the configured limit.
        
        Returns:
            int: Number of threats removed
        
        Example:
            removed = threat_store.clear_old_threats()
            print(f"Removed {removed} old threats")
        """
        try:
            if len(self.threats) <= self.max_threats:
                return 0
            
            # Calculate how many to remove
            to_remove = len(self.threats) - self.max_threats
            
            # Remove oldest threats (from the end of the list)
            self.threats = self.threats[:self.max_threats]
            
            self.logger.info(f"Cleared {to_remove} old threats, keeping {len(self.threats)}")
            return to_remove
            
        except Exception as e:
            self.logger.error(f"Error clearing old threats: {e}")
            return 0
    
    def clear_all(self) -> int:
        """
        Remove all threats from storage.
        
        This is useful for testing or when resetting the system.
        
        Returns:
            int: Number of threats removed
        """
        count = len(self.threats)
        self.threats.clear()
        self.logger.info(f"Cleared all {count} threats from store")
        return count
    
    def get_count(self) -> int:
        """
        Get the current number of stored threats.
        
        Returns:
            int: Number of threats currently in storage
        """
        return len(self.threats)
