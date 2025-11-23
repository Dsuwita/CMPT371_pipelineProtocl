import socket
import os
import struct

class FileTransferSocket:    
    CHUNK_SIZE = 1024
    HEADER_SIZE = 8
    MAX_PACKET_SIZE = HEADER_SIZE + CHUNK_SIZE
    RECV_WINDOW_SIZE = 10
    
    INITIAL_CWND = 1
    SSTHRESH_INIT = 64
    
    PKT_SYN = 0
    PKT_SYN_ACK = 1
    PKT_METADATA = 2
    PKT_DATA = 3
    PKT_ACK = 4
    PKT_EOF = 5
    PKT_FIN = 6
    PKT_FIN_ACK = 7
    
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bound = False
        self.connected = False
        self.peer_addr = None
        self.host = None
        self.port = None
        
        self.send_base = 0
        self.next_seq_num = 0
        self.recv_window = {}
        
        self.cwnd = self.INITIAL_CWND
        self.ssthresh = self.SSTHRESH_INIT
        self.dup_ack_count = 0
        self.last_ack = -1
    
    def bind(self, host='localhost', port=5000):
        """Bind the socket to a host and port for receiving"""
        self.host = host
        self.port = port
        self.sock.bind((self.host, self.port))
        self.bound = True
    
    def connect(self, host, port):
        """Establish a connection to a remote host"""
        syn_packet = struct.pack('!B', self.PKT_SYN)
        self.sock.sendto(syn_packet, (host, port))
        
        data, addr = self.sock.recvfrom(4096)
        pkt_type = struct.unpack('!B', data[0:1])[0]
        
        if pkt_type == self.PKT_SYN_ACK:
            self.connected = True
            self.peer_addr = addr
            return True
        return False
    
    def accept(self):
        """Wait for and accept an incoming connection"""
        if not self.bound:
            return False
        
        data, addr = self.sock.recvfrom(4096)
        pkt_type = struct.unpack('!B', data[0:1])[0]
        
        if pkt_type == self.PKT_SYN:
            syn_ack_packet = struct.pack('!B', self.PKT_SYN_ACK)
            self.sock.sendto(syn_ack_packet, addr)
            self.connected = True
            self.peer_addr = addr
            return True
        return False
    
    def _create_metadata_packet(self, filename, filesize):
        filename_bytes = filename.encode('utf-8')
        filename_len = len(filename_bytes)
        
        packet = struct.pack('!BH', self.PKT_METADATA, filename_len)
        packet += filename_bytes
        packet += struct.pack('!Q', filesize)
        
        return packet
    
    def _create_data_packet(self, seq_num, data):
        data_len = len(data)
        checksum = sum(data) & 0xFFFFFFFF
        packet = struct.pack('!BIHI', self.PKT_DATA, seq_num, data_len, checksum)
        packet += data
        
        return packet
    
    def _create_eof_packet(self):
        return struct.pack('!B', self.PKT_EOF)
    
    def _create_ack_packet(self, ack_num):
        return struct.pack('!BI', self.PKT_ACK, ack_num)
    
    def _parse_packet(self, packet):
        pkt_type = struct.unpack('!B', packet[0:1])[0]
        
        if pkt_type == self.PKT_METADATA:
            filename_len = struct.unpack('!H', packet[1:3])[0]
            filename = packet[3:3+filename_len].decode('utf-8')
            filesize = struct.unpack('!Q', packet[3+filename_len:3+filename_len+8])[0]
            return pkt_type, (filename, filesize)
        
        elif pkt_type == self.PKT_DATA:
            seq_num = struct.unpack('!I', packet[1:5])[0]
            data_len = struct.unpack('!H', packet[5:7])[0]
            checksum = struct.unpack('!I', packet[7:11])[0]
            data = packet[11:11+data_len]
            
            computed_checksum = sum(data) & 0xFFFFFFFF
            if computed_checksum != checksum:
                return pkt_type, None
            
            return pkt_type, (seq_num, data)
        
        elif pkt_type == self.PKT_ACK:
            ack_num = struct.unpack('!I', packet[1:5])[0]
            return pkt_type, ack_num
        
        elif pkt_type == self.PKT_EOF:
            return pkt_type, None
        
        return None, None
    
    def send_file(self, filepath):
        """Send a file over the connection"""
        if not self.connected or not self.peer_addr:
            return False
        
        if not os.path.exists(filepath):
            return False
        
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        metadata_pkt = self._create_metadata_packet(filename, filesize)
        self.sock.sendto(metadata_pkt, self.peer_addr)
        
        self.send_base = 0
        self.next_seq_num = 0
        self.cwnd = self.INITIAL_CWND
        self.ssthresh = self.SSTHRESH_INIT
        self.dup_ack_count = 0
        self.last_ack = -1
        
        chunks = []
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
        
        total_chunks = len(chunks)
        self.sock.settimeout(0.1)
        
        while self.send_base < total_chunks:
            effective_window = min(int(self.cwnd), self.RECV_WINDOW_SIZE)
            
            while self.next_seq_num < total_chunks and \
                  self.next_seq_num < self.send_base + effective_window:
                data_pkt = self._create_data_packet(self.next_seq_num, chunks[self.next_seq_num])
                self.sock.sendto(data_pkt, self.peer_addr)
                self.next_seq_num += 1
            
            try:
                data, addr = self.sock.recvfrom(4096)
                if addr == self.peer_addr:
                    pkt_type, ack_num = self._parse_packet(data)
                    if pkt_type == self.PKT_ACK:
                        if ack_num >= self.send_base and ack_num > self.last_ack:
                            self.send_base = ack_num + 1
                            self.dup_ack_count = 0
                            self.last_ack = ack_num
                            
                            if self.cwnd < self.ssthresh:
                                self.cwnd += 1
                            else:
                                self.cwnd += 1.0 / self.cwnd
                                
                        elif ack_num == self.last_ack and self.last_ack >= 0:
                            self.dup_ack_count += 1
                            
                            if self.dup_ack_count == 3:
                                self.ssthresh = max(int(self.cwnd / 2), 2)
                                self.cwnd = self.ssthresh + 3
                                self.next_seq_num = self.send_base
                                
            except socket.timeout:
                self.ssthresh = max(int(self.cwnd / 2), 2)
                self.cwnd = self.INITIAL_CWND
                self.dup_ack_count = 0
                self.next_seq_num = self.send_base
        
        self.sock.settimeout(None) 
        
        eof_pkt = self._create_eof_packet()
        self.sock.sendto(eof_pkt, self.peer_addr)
        
        return True
    
    def send_file_with_errors(self, filepath, drop_rate=0.0, corrupt_rate=0.0):
        """
        Send a file with random errors to test Go-Back-N retransmission.

        """
        import random
        
        if not self.connected or not self.peer_addr:
            return False
        
        if not os.path.exists(filepath):
            return False
        
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        metadata_pkt = self._create_metadata_packet(filename, filesize)
        self.sock.sendto(metadata_pkt, self.peer_addr)
        
        self.send_base = 0
        self.next_seq_num = 0
        self.cwnd = self.INITIAL_CWND
        self.ssthresh = self.SSTHRESH_INIT
        self.dup_ack_count = 0
        self.last_ack = -1
        
        chunks = []
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
        
        total_chunks = len(chunks)
        self.sock.settimeout(0.1)
        
        packets_sent = 0
        packets_corrupted = 0
        packets_dropped = 0
        retransmissions = 0
        already_errored = set()
        
        while self.send_base < total_chunks:
            effective_window = min(int(self.cwnd), self.RECV_WINDOW_SIZE)
            
            while self.next_seq_num < total_chunks and \
                  self.next_seq_num < self.send_base + effective_window:
                
                seq = self.next_seq_num
                
                if seq not in already_errored:
                    if random.random() < drop_rate:
                        packets_dropped += 1
                        already_errored.add(seq)
                        print(f"[ERROR] Dropped packet {seq}")
                        self.next_seq_num += 1
                        continue
                    
                    if random.random() < corrupt_rate:
                        data_pkt = bytearray(self._create_data_packet(seq, chunks[seq]))
                        if len(data_pkt) > 21:  
                            data_pkt[21] ^= 0xFF 
                        self.sock.sendto(bytes(data_pkt), self.peer_addr)
                        packets_corrupted += 1
                        packets_sent += 1
                        already_errored.add(seq)
                        print(f"[ERROR] Corrupted packet {seq}")
                        self.next_seq_num += 1
                        continue
                
                data_pkt = self._create_data_packet(seq, chunks[seq])
                self.sock.sendto(data_pkt, self.peer_addr)
                packets_sent += 1
                
                self.next_seq_num += 1
            
            try:
                data, addr = self.sock.recvfrom(4096)
                if addr == self.peer_addr:
                    pkt_type, ack_num = self._parse_packet(data)
                    if pkt_type == self.PKT_ACK:
                        if ack_num >= self.send_base and ack_num > self.last_ack:
                            self.send_base = ack_num + 1
                            self.dup_ack_count = 0
                            self.last_ack = ack_num
                            
                            if self.cwnd < self.ssthresh:
                                self.cwnd += 1
                            else:
                                self.cwnd += 1.0 / self.cwnd
                                
                        elif ack_num == self.last_ack and self.last_ack >= 0:
                            self.dup_ack_count += 1
                            
                            if self.dup_ack_count == 3:
                                self.ssthresh = max(int(self.cwnd / 2), 2)
                                self.cwnd = self.ssthresh + 3
                                print(f"[RETRANSMIT] Fast retransmit from packet {self.send_base}")
                                retransmissions += 1
                                self.next_seq_num = self.send_base
                                
            except socket.timeout:
                self.ssthresh = max(int(self.cwnd / 2), 2)
                self.cwnd = self.INITIAL_CWND
                self.dup_ack_count = 0
                print(f"[RETRANSMIT] Timeout, retransmitting from packet {self.send_base}")
                retransmissions += 1
                self.next_seq_num = self.send_base
        
        self.sock.settimeout(None)
        
        eof_pkt = self._create_eof_packet()
        self.sock.sendto(eof_pkt, self.peer_addr)
        
        print(f"\n[STATS] Total packets sent: {packets_sent}")
        print(f"[STATS] Packets corrupted: {packets_corrupted}")
        print(f"[STATS] Packets dropped: {packets_dropped}")
        print(f"[STATS] Retransmissions: {retransmissions}")
        
        return True
    
    def receive_file(self, output_dir='received_files'):
        """Receive a file over the connection"""
        if not self.connected or not self.peer_addr:
            return False
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        data, addr = self.sock.recvfrom(4096)
        if addr != self.peer_addr:
            return False
            
        pkt_type, metadata = self._parse_packet(data)
        
        if pkt_type != self.PKT_METADATA:
            return False
        
        filename, filesize = metadata
        output_path = os.path.join(output_dir, filename)
        
        self.recv_window = {}
        expected_seq = 0
        received_chunks = []
        
        while True:
            data, addr = self.sock.recvfrom(4096)
            if addr != self.peer_addr:
                continue
                
            pkt_type, content = self._parse_packet(data)
            
            if pkt_type == self.PKT_EOF:
                break
            
            elif pkt_type == self.PKT_DATA:
                if content is None:
                    ack_pkt = self._create_ack_packet(expected_seq - 1 if expected_seq > 0 else -1)
                    self.sock.sendto(ack_pkt, self.peer_addr)
                    continue
                
                seq_num, chunk = content
                
                if seq_num not in self.recv_window:
                    self.recv_window[seq_num] = chunk
                
                while expected_seq in self.recv_window:
                    received_chunks.append((expected_seq, self.recv_window[expected_seq]))
                    del self.recv_window[expected_seq]
                    expected_seq += 1
                
                ack_pkt = self._create_ack_packet(expected_seq - 1)
                self.sock.sendto(ack_pkt, self.peer_addr)
        
        received_chunks.sort(key=lambda x: x[0])
        
        with open(output_path, 'wb') as f:
            for seq_num, chunk in received_chunks:
                f.write(chunk)
        
        return True
    
    def disconnect(self):
        """Close the connection"""
        if not self.connected or not self.peer_addr:
            return
        
        fin_packet = struct.pack('!B', self.PKT_FIN)
        self.sock.sendto(fin_packet, self.peer_addr)
        
        data, addr = self.sock.recvfrom(4096)
        if addr == self.peer_addr:
            pkt_type = struct.unpack('!B', data[0:1])[0]
            if pkt_type == self.PKT_FIN_ACK:
                self.connected = False
                self.peer_addr = None
    
    def handle_disconnect(self):
        """Handle incoming disconnection request"""
        if not self.connected or not self.peer_addr:
            return
        
        data, addr = self.sock.recvfrom(4096)
        if addr == self.peer_addr:
            pkt_type = struct.unpack('!B', data[0:1])[0]
            if pkt_type == self.PKT_FIN:
                fin_ack_packet = struct.pack('!B', self.PKT_FIN_ACK)
                self.sock.sendto(fin_ack_packet, addr)
                self.connected = False
                self.peer_addr = None
    
    def close(self):
        """Close the socket"""
        self.sock.close()
