import socket
import os
import struct

class FileTransferSocket:    
    # Protocol constants
    CHUNK_SIZE = 1024
    HEADER_SIZE = 8  # 4 bytes seq_num + 4 bytes chunk_size
    MAX_PACKET_SIZE = HEADER_SIZE + CHUNK_SIZE
    RECV_WINDOW_SIZE = 10   # Flow control receiver window size
    
    # Congestion control constants
    INITIAL_CWND = 1        # Initial congestion window
    SSTHRESH_INIT = 64      # Initial slow start threshold
    
    # Packet types
    PKT_SYN = 0        # Connection request
    PKT_SYN_ACK = 1    # Connection acknowledgment
    PKT_METADATA = 2
    PKT_DATA = 3
    PKT_ACK = 4        # Acknowledgment
    PKT_EOF = 5
    PKT_FIN = 6        # Close connection
    PKT_FIN_ACK = 7    # Close acknowledgment
    
    def __init__(self):
        """Initialize the file transfer socket"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bound = False
        self.connected = False
        self.peer_addr = None
        self.host = None
        self.port = None
        
        # Flow control
        self.send_base = 0          # Oldest unacknowledged packet
        self.next_seq_num = 0       # Next sequence number to send
        self.recv_window = {}       # Received packets buffer
        
        # Congestion control
        self.cwnd = self.INITIAL_CWND       # Congestion window
        self.ssthresh = self.SSTHRESH_INIT  # Slow start threshold
        self.dup_ack_count = 0              # Duplicate ACK counter
        self.last_ack = -1                  # Last ACK received
    
    def bind(self, host='localhost', port=5000):
        """Bind the socket to a host and port for receiving"""
        self.host = host
        self.port = port
        self.sock.bind((self.host, self.port))
        self.bound = True
    
    def connect(self, host, port):
        """Establish a connection to a remote host"""
        # Send SYN packet
        syn_packet = struct.pack('!B', self.PKT_SYN)
        self.sock.sendto(syn_packet, (host, port))
        
        # Wait for SYN-ACK
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
        
        # Wait for SYN packet
        data, addr = self.sock.recvfrom(4096)
        pkt_type = struct.unpack('!B', data[0:1])[0]
        
        if pkt_type == self.PKT_SYN:
            # Send SYN-ACK
            syn_ack_packet = struct.pack('!B', self.PKT_SYN_ACK)
            self.sock.sendto(syn_ack_packet, addr)
            self.connected = True
            self.peer_addr = addr
            return True
        return False
    
    def _create_metadata_packet(self, filename, filesize):
        """Create a metadata packet containing filename and filesize"""
        # Packet format: [type(1)|filename_len(2)|filename|filesize(8)]
        filename_bytes = filename.encode('utf-8')
        filename_len = len(filename_bytes)
        
        packet = struct.pack('!BH', self.PKT_METADATA, filename_len)
        packet += filename_bytes
        packet += struct.pack('!Q', filesize)
        
        return packet
    
    def _create_data_packet(self, seq_num, data):
        """Create a data packet with sequence number, checksum, and chunk data"""
        # Packet format: [type(1)|seq_num(4)|data_len(2)|checksum(4)|data]
        data_len = len(data)
        checksum = sum(data) & 0xFFFFFFFF  # Simple checksum
        packet = struct.pack('!BIHI', self.PKT_DATA, seq_num, data_len, checksum)
        packet += data
        
        return packet
    
    def _create_eof_packet(self):
        """Create an end-of-file packet."""
        return struct.pack('!B', self.PKT_EOF)
    
    def _create_ack_packet(self, ack_num):
        """Create an acknowledgment packet."""
        # Packet format: [type(1)|ack_num(4)]
        return struct.pack('!BI', self.PKT_ACK, ack_num)
    
    def _parse_packet(self, packet):
        """Parse a received packet and return its type and contents"""
        pkt_type = struct.unpack('!B', packet[0:1])[0]
        
        if pkt_type == self.PKT_METADATA:
            # Parse metadata packet
            filename_len = struct.unpack('!H', packet[1:3])[0]
            filename = packet[3:3+filename_len].decode('utf-8')
            filesize = struct.unpack('!Q', packet[3+filename_len:3+filename_len+8])[0]
            return pkt_type, (filename, filesize)
        
        elif pkt_type == self.PKT_DATA:
            # Parse data packet
            seq_num = struct.unpack('!I', packet[1:5])[0]
            data_len = struct.unpack('!H', packet[5:7])[0]
            checksum = struct.unpack('!I', packet[7:11])[0]
            data = packet[11:11+data_len]
            
            # Verify checksum
            computed_checksum = sum(data) & 0xFFFFFFFF
            if computed_checksum != checksum:
                # Corrupted packet - return None to indicate error
                return pkt_type, None
            
            return pkt_type, (seq_num, data)
        
        elif pkt_type == self.PKT_ACK:
            # Parse ACK packet
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
        
        # Send metadata packet
        metadata_pkt = self._create_metadata_packet(filename, filesize)
        self.sock.sendto(metadata_pkt, self.peer_addr)
        
        # Reset flow control and congestion control state
        self.send_base = 0
        self.next_seq_num = 0
        self.cwnd = self.INITIAL_CWND
        self.ssthresh = self.SSTHRESH_INIT
        self.dup_ack_count = 0
        self.last_ack = -1
        
        # Read entire file into chunks
        chunks = []
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
        
        total_chunks = len(chunks)
        self.sock.settimeout(0.1)  # Set timeout for ACK reception
        
        # Send chunks
        while self.send_base < total_chunks:
            # Calculate effective window
            effective_window = min(int(self.cwnd), self.RECV_WINDOW_SIZE)
            
            # Send packets within effective window
            while self.next_seq_num < total_chunks and \
                  self.next_seq_num < self.send_base + effective_window:
                data_pkt = self._create_data_packet(self.next_seq_num, chunks[self.next_seq_num])
                self.sock.sendto(data_pkt, self.peer_addr)
                self.next_seq_num += 1
            
            # Wait for ACKs
            try:
                data, addr = self.sock.recvfrom(4096)
                if addr == self.peer_addr:
                    pkt_type, ack_num = self._parse_packet(data)
                    if pkt_type == self.PKT_ACK:
                        if ack_num >= self.send_base and ack_num > self.last_ack:
                            # New ACK received
                            self.send_base = ack_num + 1
                            self.dup_ack_count = 0
                            self.last_ack = ack_num
                            

                            if self.cwnd < self.ssthresh:
                                self.cwnd += 1
                            else:
                                self.cwnd += 1.0 / self.cwnd
                                
                        elif ack_num == self.last_ack and self.last_ack >= 0:
                            self.dup_ack_count += 1
                            
                            # Fast retransmit on 3 duplicate ACKs
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
        
        # Send EOF packet
        eof_pkt = self._create_eof_packet()
        self.sock.sendto(eof_pkt, self.peer_addr)
        
        return True
    
    def send_file_with_errors(self, filepath, corrupt_packets=None, drop_packets=None):
        """Send a file with intentional errors to test Go-Back-N retransmission. """
        if corrupt_packets is None:
            corrupt_packets = []
        if drop_packets is None:
            drop_packets = []
            
        if not self.connected or not self.peer_addr:
            return False
        
        if not os.path.exists(filepath):
            return False
        
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        # Send metadata packet
        metadata_pkt = self._create_metadata_packet(filename, filesize)
        self.sock.sendto(metadata_pkt, self.peer_addr)
        
        # Reset flow control and congestion control state
        self.send_base = 0
        self.next_seq_num = 0
        self.cwnd = self.INITIAL_CWND
        self.ssthresh = self.SSTHRESH_INIT
        self.dup_ack_count = 0
        self.last_ack = -1
        
        # Read entire file into chunks
        chunks = []
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
        
        total_chunks = len(chunks)
        self.sock.settimeout(0.1)
        
        # Track statistics
        packets_sent = 0
        packets_corrupted = 0
        packets_dropped = 0
        retransmissions = 0
        already_errored = set()  # Track packets that have already been corrupted/dropped once
        
        # Send chunks with intentional errors
        while self.send_base < total_chunks:
            effective_window = min(int(self.cwnd), self.RECV_WINDOW_SIZE)
            
            # Send packets within effective window
            while self.next_seq_num < total_chunks and \
                  self.next_seq_num < self.send_base + effective_window:
                
                seq = self.next_seq_num
                
                # Only apply errors on first transmission
                if seq in drop_packets and seq not in already_errored:
                    # Simulate packet drop (don't send) - only on first attempt
                    packets_dropped += 1
                    already_errored.add(seq)
                    print(f"[ERROR] Dropped packet {seq}")
                elif seq in corrupt_packets and seq not in already_errored:
                    # Corrupt the data by flipping some bytes - only on first attempt
                    corrupted_chunk = bytearray(chunks[seq])
                    if len(corrupted_chunk) > 10:
                        corrupted_chunk[10] ^= 0xFF  # Flip bits at position 10
                    data_pkt = self._create_data_packet(seq, bytes(corrupted_chunk))
                    self.sock.sendto(data_pkt, self.peer_addr)
                    packets_corrupted += 1
                    packets_sent += 1
                    already_errored.add(seq)
                    print(f"[ERROR] Corrupted packet {seq}")
                else:
                    # Send normal packet (or retransmission of previously errored packet)
                    data_pkt = self._create_data_packet(seq, chunks[seq])
                    self.sock.sendto(data_pkt, self.peer_addr)
                    packets_sent += 1
                
                self.next_seq_num += 1
            
            # Wait for ACKs
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
        
        # Send EOF packet
        eof_pkt = self._create_eof_packet()
        self.sock.sendto(eof_pkt, self.peer_addr)
        
        # Print statistics
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
        
        # Receive metadata packet
        data, addr = self.sock.recvfrom(4096)
        if addr != self.peer_addr:
            return False
            
        pkt_type, metadata = self._parse_packet(data)
        
        if pkt_type != self.PKT_METADATA:
            return False
        
        filename, filesize = metadata
        output_path = os.path.join(output_dir, filename)
        
        # Reset receive window
        self.recv_window = {}
        expected_seq = 0
        received_chunks = []
        
        # Receive data packets with flow control
        while True:
            data, addr = self.sock.recvfrom(4096)
            if addr != self.peer_addr:
                continue
                
            pkt_type, content = self._parse_packet(data)
            
            if pkt_type == self.PKT_EOF:
                break
            
            elif pkt_type == self.PKT_DATA:
                if content is None:
                    # Corrupted packet detected - send ACK for last good packet
                    ack_pkt = self._create_ack_packet(expected_seq - 1 if expected_seq > 0 else -1)
                    self.sock.sendto(ack_pkt, self.peer_addr)
                    continue
                
                seq_num, chunk = content
                
                # Store packet in window
                if seq_num not in self.recv_window:
                    self.recv_window[seq_num] = chunk
                
                # Deliver in-order packets
                while expected_seq in self.recv_window:
                    received_chunks.append((expected_seq, self.recv_window[expected_seq]))
                    del self.recv_window[expected_seq]
                    expected_seq += 1
                
                # Send ACK for highest in-order packet received
                ack_pkt = self._create_ack_packet(expected_seq - 1)
                self.sock.sendto(ack_pkt, self.peer_addr)
        
        # Sort chunks by sequence number and write to file
        received_chunks.sort(key=lambda x: x[0])
        
        with open(output_path, 'wb') as f:
            for seq_num, chunk in received_chunks:
                f.write(chunk)
        
        return True
    
    def disconnect(self):
        """Close the connection"""
        if not self.connected or not self.peer_addr:
            return
        
        # Send FIN packet
        fin_packet = struct.pack('!B', self.PKT_FIN)
        self.sock.sendto(fin_packet, self.peer_addr)
        
        # Wait for FIN-ACK
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
        
        # Wait for FIN packet
        data, addr = self.sock.recvfrom(4096)
        if addr == self.peer_addr:
            pkt_type = struct.unpack('!B', data[0:1])[0]
            if pkt_type == self.PKT_FIN:
                # Send FIN-ACK
                fin_ack_packet = struct.pack('!B', self.PKT_FIN_ACK)
                self.sock.sendto(fin_ack_packet, addr)
                self.connected = False
                self.peer_addr = None
    
    def close(self):
        """Close the socket"""
        self.sock.close()
