from file_transfer_protocol import FileTransferSocket
import os

if __name__ == "__main__":
    # Create a sender socket
    sender = FileTransferSocket()
    
    # Get connection info
    host = input("Enter receiver host (default: localhost): ").strip() or "localhost"
    port = int(input("Enter receiver port (default: 5000): ").strip() or "5000")
    
    # Establish connection
    print(f"Connecting to {host}:{port}...")
    if not sender.connect(host, port):
        print("Failed to connect")
        sender.close()
        exit(1)
    
    print("Connected!")
    
    # Get file to send
    filepath = input("Enter the path of the file to send: ")
    
    if not os.path.exists(filepath):
        print(f"Error: File {filepath} not found")
    else:
        print("Sending file...")
        if sender.send_file(filepath):
            print("File sent successfully!")
        else:
            print("Failed to send file")
    
    # Close connection
    print("Closing connection...")
    sender.disconnect()
    sender.close()
