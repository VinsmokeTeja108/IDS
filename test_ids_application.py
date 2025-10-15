"""Test for IDSApplication class"""

import os
import tempfile
import yaml
from unittest.mock import Mock, patch, MagicMock
from ids.ids_application import IDSApplication
from ids.models.exceptions import IDSException, ConfigurationException


def create_test_config():
    """Create a temporary test configuration file"""
    config_data = {
        'email': {
            'smtp_host': 'smtp.test.com',
            'smtp_port': 587,
            'use_tls': True,
            'username': 'test@test.com',
            'password': 'testpass',
            'recipients': ['admin@test.com']
        },
        'detection': {
            'network_interface': 'eth0',
            'port_scan_threshold': 10,
            'icmp_scan_threshold': 5,
            'brute_force_threshold': 5
        },
        'logging': {
            'log_level': 'INFO',
            'log_file': 'test_ids.log',
            'max_log_size_mb': 100,
            'backup_count': 5
        },
        'notification': {
            'batch_window_seconds': 300,
            'batch_threshold': 3,
            'retry_attempts': 3,
            'retry_delay_seconds': 10
        }
    }
    
    # Create temporary config file
    fd, path = tempfile.mkstemp(suffix='.yaml')
    with os.fdopen(fd, 'w') as f:
        yaml.dump(config_data, f)
    
    return path


def test_ids_application_initialization():
    """Test that IDSApplication initializes all components correctly"""
    config_path = create_test_config()
    
    try:
        # Create IDS application
        ids_app = IDSApplication(config_path)
        
        # Verify initial state
        assert ids_app.config_path == config_path
        assert ids_app.config_manager is None
        assert ids_app.logger is None
        assert ids_app.packet_capture is None
        assert ids_app.detection_engine is None
        assert ids_app.threat_analyzer is None
        assert ids_app.notification_service is None
        assert ids_app.attacker_identifier is None
        assert ids_app.is_running is False
        
        # Initialize components
        ids_app.initialize()
        
        # Verify all components are initialized
        assert ids_app.config_manager is not None
        assert ids_app.logger is not None
        assert ids_app.packet_capture is not None
        assert ids_app.detection_engine is not None
        assert ids_app.threat_analyzer is not None
        assert ids_app.notification_service is not None
        assert ids_app.attacker_identifier is not None
        
        # Verify detection engine has detectors registered
        stats = ids_app.detection_engine.get_statistics()
        assert stats['registered_detectors'] == 5  # 5 detectors registered
        assert 'PortScanDetector' in stats['detector_types']
        assert 'ICMPScanDetector' in stats['detector_types']
        assert 'BruteForceDetector' in stats['detector_types']
        assert 'MalwareDetector' in stats['detector_types']
        assert 'DataExfiltrationDetector' in stats['detector_types']
        
        print("✓ IDSApplication initialization test passed")
        
    finally:
        # Clean up
        if os.path.exists(config_path):
            os.remove(config_path)
        if os.path.exists('test_ids.log'):
            os.remove('test_ids.log')


def test_ids_application_initialization_with_missing_config():
    """Test that IDSApplication handles missing configuration file"""
    # Use non-existent config file
    ids_app = IDSApplication('nonexistent_config.yaml')
    
    # Should initialize with default config (no exception)
    ids_app.initialize()
    
    # Verify components are initialized with defaults
    assert ids_app.config_manager is not None
    assert ids_app.logger is not None
    
    print("✓ IDSApplication missing config test passed")
    
    # Clean up
    if os.path.exists('ids.log'):
        os.remove('ids.log')


def test_ids_application_run_without_initialization():
    """Test that run() raises exception if not initialized"""
    config_path = create_test_config()
    
    try:
        ids_app = IDSApplication(config_path)
        
        # Try to run without initialization
        try:
            ids_app.run()
            assert False, "Should have raised IDSException"
        except IDSException as e:
            assert "not initialized" in str(e)
        
        print("✓ IDSApplication run without initialization test passed")
        
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)


@patch('ids.ids_application.PacketCaptureEngine')
def test_ids_application_shutdown(mock_capture_class):
    """Test graceful shutdown of IDSApplication"""
    config_path = create_test_config()
    
    try:
        # Create mock packet capture
        mock_capture = Mock()
        mock_capture.is_capturing = True
        mock_capture_class.return_value = mock_capture
        
        # Create and initialize IDS application
        ids_app = IDSApplication(config_path)
        ids_app.initialize()
        
        # Shutdown
        ids_app.shutdown()
        
        # Verify shutdown was called on packet capture
        mock_capture.stop_capture.assert_called_once()
        
        # Verify shutdown flag is set
        assert ids_app._shutdown_requested is True
        
        print("✓ IDSApplication shutdown test passed")
        
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)
        if os.path.exists('test_ids.log'):
            os.remove('test_ids.log')


def test_ids_application_component_wiring():
    """Test that all components are properly wired together"""
    config_path = create_test_config()
    
    try:
        ids_app = IDSApplication(config_path)
        ids_app.initialize()
        
        # Verify threat analyzer has severity classifier
        assert ids_app.threat_analyzer.severity_classifier is not None
        
        # Verify notification service has email service and logger
        assert ids_app.notification_service.email_service is not None
        assert ids_app.notification_service.logger is not None
        
        # Verify detection engine has detectors
        assert len(ids_app.detection_engine._detectors) > 0
        
        # Verify attacker identifier is initialized
        assert ids_app.attacker_identifier is not None
        assert ids_app.attacker_identifier.threshold == 2
        
        print("✓ IDSApplication component wiring test passed")
        
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)
        if os.path.exists('test_ids.log'):
            os.remove('test_ids.log')


if __name__ == '__main__':
    print("Running IDSApplication tests...\n")
    
    test_ids_application_initialization()
    test_ids_application_initialization_with_missing_config()
    test_ids_application_run_without_initialization()
    test_ids_application_shutdown()
    test_ids_application_component_wiring()
    
    print("\n✓ All IDSApplication tests passed!")
