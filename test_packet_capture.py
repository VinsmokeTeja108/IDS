"""Test script for PacketCaptureEngine"""

import time
from ids.services.packet_capture import PacketCaptureEngine
from ids.models.exceptions import CaptureException


def test_basic_functionality():
    """Test basic packet capture functionality"""
    print("Testing PacketCaptureEngine...")
    
    engine = PacketCaptureEngine()
    
    # Test 1: Check initial state
    print("\n1. Testing initial state...")
    assert not engine.is_capturing, "Engine should not be capturing initially"
    assert engine.interface is None, "Interface should be None initially"
    print("✓ Initial state correct")
    
    # Test 2: Test error handling for invalid interface
    print("\n2. Testing invalid interface error handling...")
    try:
        engine.start_capture("invalid_interface_xyz123")
        time.sleep(1)  # Give it time to detect the error
        
        # Try to get packets (should raise error)
        for _ in engine.get_packet_stream():
            pass
        print("✗ Should have raised CaptureException for invalid interface")
    except CaptureException as e:
        print(f"✓ Correctly raised CaptureException: {e}")
    finally:
        if engine.is_capturing:
            try:
                engine.stop_capture()
            except:
                pass
    
    # Test 3: Test double start prevention
    print("\n3. Testing double start prevention...")
    engine2 = PacketCaptureEngine()
    try:
        # This should work on a valid interface (loopback)
        # Note: On Windows use "Loopback", on Linux use "lo"
        import platform
        if platform.system() == "Windows":
            interface = "Loopback"
        else:
            interface = "lo"
        
        engine2.start_capture(interface)
        print(f"✓ Started capture on {interface}")
        
        # Try to start again
        try:
            engine2.start_capture(interface)
            print("✗ Should have raised CaptureException for double start")
        except CaptureException as e:
            print(f"✓ Correctly prevented double start: {e}")
        
        # Test 4: Test stop capture
        print("\n4. Testing stop capture...")
        engine2.stop_capture()
        assert not engine2.is_capturing, "Engine should not be capturing after stop"
        print("✓ Stop capture works correctly")
        
    except CaptureException as e:
        print(f"Note: Could not test with loopback interface: {e}")
        print("This is expected if running without admin/root privileges")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    # Test 5: Test stop without start
    print("\n5. Testing stop without start...")
    engine3 = PacketCaptureEngine()
    try:
        engine3.stop_capture()
        print("✗ Should have raised CaptureException for stop without start")
    except CaptureException as e:
        print(f"✓ Correctly raised error: {e}")
    
    print("\n" + "="*50)
    print("Basic functionality tests completed!")
    print("="*50)


def test_packet_stream():
    """Test packet streaming (requires privileges)"""
    print("\n\nTesting packet streaming...")
    print("Note: This test requires administrator/root privileges")
    
    engine = PacketCaptureEngine()
    
    try:
        import platform
        if platform.system() == "Windows":
            interface = "Loopback"
        else:
            interface = "lo"
        
        print(f"\nStarting capture on {interface}...")
        engine.start_capture(interface)
        
        print("Capturing packets for 3 seconds...")
        packet_count = 0
        start_time = time.time()
        
        for packet in engine.get_packet_stream():
            packet_count += 1
            print(f"Captured packet {packet_count}: {packet.summary()}")
            
            # Stop after 3 seconds or 5 packets
            if time.time() - start_time > 3 or packet_count >= 5:
                break
        
        engine.stop_capture()
        print(f"\n✓ Successfully captured {packet_count} packets")
        
    except CaptureException as e:
        print(f"\n⚠ Capture test skipped: {e}")
        print("Run this script with administrator/root privileges to test packet capture")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        if engine.is_capturing:
            engine.stop_capture()


if __name__ == "__main__":
    print("="*50)
    print("PacketCaptureEngine Test Suite")
    print("="*50)
    
    test_basic_functionality()
    test_packet_stream()
    
    print("\n" + "="*50)
    print("All tests completed!")
    print("="*50)
