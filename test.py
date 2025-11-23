#!/usr/bin/env python3
"""Test Go-Back-N retransmission with intentional errors"""

import threading
import time
from file_transfer_protocol import FileTransferSocket
import os
import hashlib

def receiver_thread():
    receiver = FileTransferSocket()
    receiver.bind('localhost', 5557)
    print("[Receiver] Ready and waiting for connection...\n")
    
    if receiver.accept():
        print("[Receiver] Connection established\n")
        if receiver.receive_file('received_files'):
            print("\n[Receiver] File received successfully!")
        receiver.handle_disconnect()
    receiver.close()

def sender_thread():
    time.sleep(0.5)
    sender = FileTransferSocket()
    print("[Sender] Connecting to receiver...")
    
    if sender.connect('localhost', 5557):
        print("[Sender] Connected!\n")
        print("=" * 60)
        print("Testing Go-Back-N with random errors")
        print("=" * 60)
        print()
        
        start = time.time()
        # Randomly drop 5% and corrupt 3% of packets
        if sender.send_file_with_errors('large_test.bin', 
                                       drop_rate=0.05, 
                                       corrupt_rate=0.03):
            elapsed = time.time() - start
            filesize = os.path.getsize('large_test.bin')
            print(f"\n[Sender] Transfer completed in {elapsed:.2f}s")
            print(f"[Sender] Throughput: {filesize/elapsed/1024:.2f} KB/s")
        
        sender.disconnect()
    sender.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Go-Back-N Retransmission Test")
    print("=" * 60)
    print()
    
    # Ensure test file exists
    if not os.path.exists('large_test.bin'):
        print("Creating test file...")
        os.system('dd if=/dev/urandom of=large_test.bin bs=1024 count=100 2>/dev/null')
    
    receiver = threading.Thread(target=receiver_thread, daemon=True)
    receiver.start()
    sender_thread()
    receiver.join(timeout=15)
    
    print("\n" + "=" * 60)
    print("Verifying file integrity...")
    print("=" * 60)
    
    # Verify transfer
    if os.path.exists('received_files/large_test.bin'):
        with open('large_test.bin', 'rb') as f:
            orig_hash = hashlib.md5(f.read()).hexdigest()
        with open('received_files/large_test.bin', 'rb') as f:
            recv_hash = hashlib.md5(f.read()).hexdigest()
        
        orig_size = os.path.getsize('large_test.bin')
        recv_size = os.path.getsize('received_files/large_test.bin')
        
        print(f"\nOriginal file: {orig_size} bytes, MD5: {orig_hash}")
        print(f"Received file: {recv_size} bytes, MD5: {recv_hash}")
        
        if orig_hash == recv_hash:
            print("\nSUCCESS: File transferred correctly")
        else:
            print("\nFAILURE: File corrupted")
    else:
        print("\nFAILURE: File not received")
    
    print("=" * 60)
