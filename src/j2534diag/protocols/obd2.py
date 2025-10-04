from typing import Dict, Any, Optional

class OBDIIProtocol:
    PIDS = {  # (unchanged)
        0x00:"PIDs supported [01-20]", 0x01:"Monitor status since DTCs cleared", 0x02:"Freeze DTC",
        0x03:"Fuel system status", 0x04:"Calculated engine load", 0x05:"Engine coolant temperature",
        0x06:"Short term fuel trim—Bank 1", 0x07:"Long term fuel trim—Bank 1",
        0x0C:"Engine RPM", 0x0D:"Vehicle speed", 0x0E:"Timing advance", 0x0F:"Intake air temperature",
        0x10:"MAF air flow rate", 0x11:"Throttle position", 0x1C:"OBD standards", 0x20:"PIDs supported [21-40]",
        0x21:"Distance with MIL on", 0x2F:"Fuel Tank Level", 0x33:"Barometric Pressure",
        0x42:"Control module voltage", 0x46:"Ambient air temp", 0x51:"Fuel Type"
    }

    @staticmethod
    def build_obd_request(mode: int, pid: int, extra_bytes: bytes = b'') -> bytes:
        length = 2 + len(extra_bytes)
        return bytes([length, mode & 0xFF, pid & 0xFF]) + extra_bytes

    @staticmethod
    def parse_obd_response(data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 3: return None
        return {'length': data[0], 'mode': data[1], 'pid': data[2] if len(data) > 2 else None,
                'data': data[3:] if len(data) > 3 else b''}

    @staticmethod
    def decode_dtc(code_bytes: bytes) -> str:
        if len(code_bytes) < 2: return "Unknown"
        prefix_map = {0:'P',1:'C',2:'B',3:'U'}
        prefix = prefix_map.get((code_bytes[0] >> 6) & 0x03, 'P')
        code_num = ((code_bytes[0] & 0x3F) << 8) | code_bytes[1]
        return f"{prefix}{code_num:04X}"
