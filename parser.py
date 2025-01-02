#!/usr/bin/env python3

def check_dependencies():
    """Check if required packages are installed"""
    missing_packages = []
    
    try:
        import pyshark
    except ImportError:
        missing_packages.append("pyshark")
        
    if missing_packages:
        print("Missing required packages. Please install them using:")
        print(f"pip install {' '.join(missing_packages)}")
        print("\nNote: pyshark requires Wireshark to be installed on your system")
        return False
    return True

import sys
from collections import defaultdict

def parse_gatt_operations(capture_file):
    """Parse all BLE GATT operations from capture file"""
    import pyshark  # Import here after check
    cap = pyshark.FileCapture(capture_file, display_filter='btatt')
    operations = defaultdict(list)
    timeline = []  # For tracking chronological order of all events
    
    # Extended GATT operation types mapping
    opcode_names = {
        '0x01': 'Error Response',
        '0x02': 'Exchange MTU Request',
        '0x03': 'Exchange MTU Response',
        '0x04': 'Find Information Request',
        '0x05': 'Find Information Response',
        '0x06': 'Find By Type Value Request',
        '0x07': 'Find By Type Value Response',
        '0x08': 'Read By Type Request',
        '0x09': 'Read By Type Response',
        '0x0a': 'Read Request',
        '0x0b': 'Read Response',
        '0x0c': 'Read Blob Request',
        '0x0d': 'Read Blob Response',
        '0x0e': 'Read Multiple Request',
        '0x0f': 'Read Multiple Response',
        '0x10': 'Read By Group Type Request',
        '0x11': 'Read By Group Type Response',
        '0x12': 'Write Request',
        '0x13': 'Write Response',
        '0x16': 'Prepare Write Request',
        '0x17': 'Prepare Write Response',
        '0x18': 'Execute Write Request',
        '0x19': 'Execute Write Response',
        '0x1b': 'Handle Value Notification',
        '0x1d': 'Handle Value Indication',
        '0x1e': 'Handle Value Confirmation',
        '0x52': 'Write Command',
        '0xd2': 'Signed Write Command'
    }
    
    try:
        for pkt in cap:
            if not hasattr(pkt, 'btatt'):
                continue
                
            # Get basic packet info
            opcode = getattr(pkt.btatt, 'opcode', 'Unknown')
            op_name = opcode_names.get(opcode, f'Unknown Operation ({opcode})')
            
            # Extract handle correctly based on operation type
            handle = '0'
            if hasattr(pkt.btatt, 'handle'):
                handle = pkt.btatt.handle
            elif hasattr(pkt.btatt, 'starting_handle'):
                handle = pkt.btatt.starting_handle
                
            handle = int(handle, 16)
            
            # Build operation details
            operation = {
                'time': float(pkt.frame_info.time_epoch),
                'frame': pkt.frame_info.number,
                'type': op_name,
                'handle': handle
            }
            
            # Extract data fields based on operation type
            if hasattr(pkt.btatt, 'value'):
                operation['data'] = pkt.btatt.value
            elif hasattr(pkt.btatt, 'uuid'):
                operation['data'] = f"UUID: {pkt.btatt.uuid}"
            elif hasattr(pkt.btatt, 'starting_handle') and hasattr(pkt.btatt, 'ending_handle'):
                operation['data'] = f"Range: {pkt.btatt.starting_handle}-{pkt.btatt.ending_handle}"
                
            # Add connection handle if available
            if hasattr(pkt, 'btle'):
                operation['connection'] = getattr(pkt.btle, 'connection_handle', 'Unknown')
                
            operations[handle].append(operation)
            timeline.append(operation)
            
    except FileNotFoundError:
        print(f"Error: Capture file '{capture_file}' not found")
        return
    except Exception as e:
        print(f"Error processing capture: {e}")
        return
    
    # Print chronological summary
    print("\n=== Communication Flow Summary ===")
    last_time = None
    for event in sorted(timeline, key=lambda x: x['time']):
        time = event['time']
        # Calculate relative time from first event
        if last_time is None:
            last_time = time
            rel_time = 0
        else:
            rel_time = time - last_time
                
        frame = event['frame']
        op_type = event['type']
        handle = event['handle']
        data = event.get('data', '')
        data_summary = f": {data[:30]}..." if len(data) > 30 else f": {data}" if data else ""
            
        print(f"+{rel_time:.3f}s Frame {frame}: Handle 0x{handle:04x} - {op_type}{data_summary}")
    
    # Print detailed analysis by handle
    print("\n=== Detailed Analysis by Handle ===")
    for handle, handle_ops in sorted(operations.items()):
        print(f"\nHandle: 0x{handle:04x}")
        
        # Group operations by type
        by_type = defaultdict(list)
        for op in handle_ops:
            by_type[op['type']].append(op)
            
        # Print summary for each operation type
        for op_type, ops in sorted(by_type.items()):
            print(f"\n{op_type} ({len(ops)} operations):")
            for op in ops:
                frame = op['frame']
                conn = op.get('connection', 'N/A')
                data = op.get('data', '')
                if data:
                    print(f"  Frame {frame} (Conn: {conn}): {data}")
                else:
                    print(f"  Frame {frame} (Conn: {conn})")
            
            # For write operations, show combined data if present
            if ('Write' in op_type or 'Notification' in op_type) and len(ops) > 1:
                combined = ''.join(op.get('data', '') for op in ops if op.get('data'))
                if combined:
                    print(f"\n  Combined data: {combined}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python parse_gatt.py <capture.pcapng>")
        sys.exit(1)
        
    if not check_dependencies():
        sys.exit(1)
        
    capture_file = sys.argv[1]
    parse_gatt_operations(capture_file)

if __name__ == '__main__':
    main()
