# Implementation Plan

- [x] 1. Set up project structure and core data models




  - Create directory structure: `ids/` with subdirectories for `detectors/`, `services/`, `models/`, `utils/`
  - Implement core data models: `ThreatType`, `SeverityLevel`, `ThreatEvent`, `ThreatAnalysis`, `Config` enums and dataclasses
  - Create custom exception hierarchy: `IDSException`, `CaptureException`, `DetectionException`, `NotificationException`, `ConfigurationException`
  - _Requirements: 5.1, 6.4_

- [ ] 2. Implement configuration management system
  - [x] 2.1 Create `ConfigurationManager` class with YAML loading





    - Implement `load_config()` method to parse YAML configuration file
    - Implement `get()` method for retrieving configuration values
    - Implement `reload()` method for runtime configuration updates
    - Add validation for required configuration fields (email, detection thresholds)
    - Implement fallback to secure defaults when configuration is invalid
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_
  
  - [x] 2.2 Create sample configuration file template





    - Write `config.yaml.example` with all configuration sections (email, detection, logging, notification)
    - Include comments explaining each configuration option
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 3. Implement logging system
  - [x] 3.1 Create `IDSLogger` class with JSON formatting





    - Implement `log_threat()` method for logging threat events
    - Implement `log_notification()` method for logging email notifications
    - Implement `log_system_event()` method for system events
    - Configure log rotation based on file size and backup count
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_
  
  - [ ]* 3.2 Write unit tests for logger
    - Test JSON log formatting
    - Test log rotation behavior
    - _Requirements: 6.4_

- [ ] 4. Implement email notification system
  - [x] 4.1 Create `EmailService` class with SMTP support





    - Implement `send_email()` method with SMTP connection and TLS support
    - Implement retry logic with exponential backoff (up to 3 attempts)
    - Implement `format_threat_email()` method to generate email subject and body from `ThreatAnalysis`
    - Add error handling for SMTP connection failures and authentication errors
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [x] 4.2 Create `NotificationService` class with batching logic





    - Implement `notify()` method for single threat notifications
    - Implement `batch_notifications()` method for batched alerts
    - Implement batching window logic (collect threats within 5-minute window)
    - Implement immediate notification for Critical severity threats
    - Integrate with `IDSLogger` to log notification status
    - _Requirements: 3.6, 3.5_
  
  - [ ]* 4.3 Write unit tests for email service
    - Test email formatting with mock threat data
    - Test retry logic with mock SMTP failures
    - Test batching logic with multiple threats
    - _Requirements: 3.1, 3.5, 3.6_

- [ ] 5. Implement threat analysis and severity classification
  - [x] 5.1 Create `SeverityClassifier` class










    - Implement `classify()` method with base severity assignment by threat type
    - Implement escalation logic based on frequency and source reputation
    - Implement severity justification generation
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  
  - [x] 5.2 Create `ThreatAnalyzer` class








    - Implement `analyze()` method to generate `ThreatAnalysis` from `ThreatEvent`
    - Implement `get_recommendations()` method with threat-specific remediation steps
    - Create recommendation templates for each threat type (port scan, ICMP scan, malware, brute force, data exfiltration)
    - Integrate with `SeverityClassifier` for severity assignment
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_
  
  - [ ]* 5.3 Write unit tests for analyzer and classifier
    - Test severity classification for different threat types
    - Test recommendation generation
    - Test escalation logic
    - _Requirements: 2.1, 2.2, 2.3, 4.1_

- [ ] 6. Implement packet capture engine
  - [x] 6.1 Create `PacketCaptureEngine` class using Scapy





    - Implement `start_capture()` method to begin packet sniffing on specified interface
    - Implement `stop_capture()` method to stop packet capture
    - Implement `get_packet_stream()` method to yield captured packets
    - Run packet capture in separate thread to avoid blocking
    - Add error handling for interface not found and permission errors
    - _Requirements: 7.1, 7.3, 7.4_
  
  - [ ]* 6.2 Write unit tests for packet capture
    - Test capture start/stop functionality with mock interface
    - Test error handling for invalid interface
    - _Requirements: 7.1, 7.4_

- [ ] 7. Implement threat detection engine and detectors
  - [x] 7.1 Create `ThreatDetector` abstract base class





    - Define abstract `detect()` method interface
    - _Requirements: 1.1_
  
  - [x] 7.2 Implement `PortScanDetector` class





    - Track SYN packets without corresponding ACK responses
    - Detect multiple port connection attempts from single source IP
    - Trigger alert when threshold exceeded (configurable, default 10 ports in 60 seconds)
    - Generate `ThreatEvent` with port scan details
    - _Requirements: 1.3_
  
  - [x] 7.3 Implement `ICMPScanDetector` class





    - Monitor ICMP echo request packets
    - Track ICMP requests to multiple destination hosts from single source
    - Trigger alert when threshold exceeded (configurable, default 5 hosts in 30 seconds)
    - Generate `ThreatEvent` with ICMP scan details
    - _Requirements: 1.4_
  
  - [x] 7.4 Implement `BruteForceDetector` class





    - Track failed authentication attempts (monitor TCP RST packets on common auth ports: 22, 3389, 21)
    - Trigger alert when threshold exceeded (configurable, default 5 attempts in 60 seconds)
    - Generate `ThreatEvent` with brute force details
    - _Requirements: 1.5_
  
  - [x] 7.5 Implement `MalwareDetector` class





    - Implement basic signature-based detection using pattern matching on packet payloads
    - Create signature database with common malware patterns
    - Scan packet payloads for known malicious signatures
    - Generate `ThreatEvent` with malware details
    - _Requirements: 1.2_
  
  - [x] 7.6 Implement `DataExfiltrationDetector` class





    - Monitor outbound traffic volume per destination
    - Track unusual large data transfers
    - Trigger alert for suspicious outbound patterns
    - Generate `ThreatEvent` with exfiltration details
    - _Requirements: 1.6_
  
  - [x] 7.7 Implement `AttackerIdentifier` class





    - Aggregate threat events by source IP
    - Identify IPs with multiple threat indicators
    - Generate `ThreatEvent` for identified attackers
    - _Requirements: 1.1_
  
  - [x] 7.8 Create `ThreatDetectionEngine` orchestrator class





    - Implement `register_detector()` method to add detector modules
    - Implement `analyze_packet()` method to run all detectors on each packet
    - Coordinate between detectors and maintain detection state
    - Return `ThreatEvent` when threat is detected
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_
  
  - [ ]* 7.9 Write unit tests for detectors
    - Test each detector with crafted packets simulating attacks
    - Test threshold logic for port scan and ICMP scan detectors
    - Test malware signature matching
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

- [ ] 8. Implement main application orchestration
  - [x] 8.1 Create main `IDSApplication` class





    - Implement initialization: load configuration, set up logging, initialize all components
    - Implement main loop: capture packets → detect threats → analyze → notify
    - Implement graceful shutdown handling
    - Wire together all components: `PacketCaptureEngine`, `ThreatDetectionEngine`, `ThreatAnalyzer`, `NotificationService`
    - _Requirements: 1.1, 2.1, 3.1, 4.1, 5.1, 6.1, 7.1_
  
  - [x] 8.2 Create command-line interface





















    - Implement argument parsing for config file path and interface selection
    - Add options for verbose logging and dry-run mode
    - Implement startup banner with system information
    - _Requirements: 5.1, 7.1_
  
  - [x] 8.3 Create entry point script





    - Create `main.py` or `ids.py` as entry point
    - Add privilege check (require root/admin for packet capture)
    - Add signal handlers for graceful shutdown (SIGINT, SIGTERM)
    - _Requirements: 7.1_

- [ ] 9. Create installation and deployment files
  - [-] 9.1 Create `requirements.txt` with dependencies



    - List all Python dependencies: scapy, pyyaml
    - Specify version constraints
    - _Requirements: 5.1_
  
  - [ ] 9.2 Create README.md with setup instructions
    - Document installation steps
    - Document configuration file format
    - Document running the IDS
    - Include examples and troubleshooting tips
    - Document privilege requirements
    - _Requirements: 5.1, 7.1_
  
  - [ ] 9.3 Create systemd service file for Linux deployment
    - Create `ids.service` file for systemd
    - Configure service to run as root with auto-restart
    - _Requirements: 7.1_

- [ ]* 10. Create integration tests
  - Create end-to-end test using PCAP files with various attack scenarios
  - Test complete flow: packet capture → detection → analysis → email notification
  - Use mock SMTP server to verify email sending
  - _Requirements: 1.1, 2.1, 3.1, 4.1_
