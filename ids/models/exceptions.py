"""Custom exception hierarchy for the IDS"""


class IDSException(Exception):
    """Base exception for all IDS-related errors"""
    pass


class CaptureException(IDSException):
    """Exception raised for packet capture related errors"""
    pass


class DetectionException(IDSException):
    """Exception raised for threat detection errors"""
    pass


class NotificationException(IDSException):
    """Exception raised for email notification errors"""
    pass


class ConfigurationException(IDSException):
    """Exception raised for configuration errors"""
    pass
