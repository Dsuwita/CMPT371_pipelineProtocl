from file_transfer_protocol import FileTransferSocket

if __name__ == "__main__":
    # Get configuration
    host = input("Enter host to bind (default: localhost): ").strip() or "localhost"
    port = int(input("Enter port to bind (default: 5000): ").strip() or "5000")
    output_dir = input("Enter output directory (default: received_files): ").strip() or "received_files"
    
    # Create a receiver socket and bind it
    receiver = FileTransferSocket()
    receiver.bind(host, port)
    
    print(f"\nReceiver ready on {host}:{port}")
    print("Waiting for connection...\n")
    
    try:
        # Accept connection
        if not receiver.accept():
            print("Failed to accept connection")
            receiver.close()
            exit(1)
        
        print(f"Connected to {receiver.peer_addr}")
        print("Receiving file...")
        
        # Receive file
        if receiver.receive_file(output_dir):
            print("File received successfully!")
        else:
            print("Failed to receive file")
        
        # Handle disconnection
        print("Closing connection...")
        receiver.handle_disconnect()
        
    except KeyboardInterrupt:
        print("\nReceiver stopped")
    finally:
        receiver.close()
