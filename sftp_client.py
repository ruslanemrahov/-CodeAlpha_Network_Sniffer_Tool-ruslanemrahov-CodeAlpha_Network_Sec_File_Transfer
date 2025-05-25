import os
import socket
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import logging
from datetime import datetime
import argparse
import getpass
import time
import sys

# Configuration
CONFIG = {
    "host": "localhost",
    "port": 5000,
    "buffer_size": 8192,
    "salt": b"salt_1234_secure_transfer",
    "download_dir": "client_downloads",
    "log_file": "client.log",
    "timeout": 30
}

# Set up logging
logging.basicConfig(
    filename=CONFIG['log_file'],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SFTP_Client:
    def __init__(self):
        self.client_socket = None
        self.connected = False
        self.authenticated = False
        self.session_key = None
        self.username = None
        
        # Create necessary directories
        os.makedirs(CONFIG['download_dir'], exist_ok=True)
    
    def connect(self, host=None, port=None):
        host = host or CONFIG['host']
        port = port or CONFIG['port']
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(CONFIG['timeout'])
            self.client_socket.connect((host, port))
            self.connected = True
            logging.info(f"Connected to {host}:{port}")
            print(f"🔗 Connected to {host}:{port}")
            return True
        except socket.timeout:
            print(f"❌ Connection timeout to {host}:{port}")
            return False
        except ConnectionRefusedError:
            print(f"❌ Connection refused by {host}:{port}")
            return False
        except Exception as e:
            logging.error(f"Connection error: {str(e)}")
            print(f"❌ Connection error: {str(e)}")
            return False
    
    def disconnect(self):
        if self.connected and self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.connected = False
            self.authenticated = False
            self.session_key = None
            logging.info("Disconnected from server")
            print("🔌 Disconnected from server")
    
    def send_request(self, request):
        if not self.connected:
            return {"status": "error", "message": "Not connected to server"}
            
        try:
            request_data = json.dumps(request).encode('utf-8')
            self.client_socket.send(request_data)
            
            response_data = self.client_socket.recv(CONFIG['buffer_size'])
            if not response_data:
                return {"status": "error", "message": "No response from server"}
                
            response = json.loads(response_data.decode('utf-8'))
            return response
        except socket.timeout:
            return {"status": "error", "message": "Request timeout"}
        except ConnectionResetError:
            self.connected = False
            return {"status": "error", "message": "Connection lost"}
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid response format"}
        except Exception as e:
            logging.error(f"Communication error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def authenticate(self, username, password):
        hashed_password = self.hash_password(password)
        request = {
            "command": "auth",
            "username": username,
            "password": hashed_password
        }
        
        response = self.send_request(request)
        
        if response.get('status') == "success":
            self.authenticated = True
            self.session_key = PBKDF2(hashed_password.encode(), CONFIG['salt'], dkLen=32)
            self.username = username
            logging.info(f"Authenticated as {username}")
            print(f"✅ Authenticated as {username}")
        else:
            print(f"❌ Authentication failed: {response.get('message', 'Unknown error')}")
        
        return response
    
    def register(self, username, password):
        request = {
            "command": "register",
            "username": username,
            "password": self.hash_password(password)
        }
        response = self.send_request(request)
        
        if response.get('status') == "success":
            print(f"✅ User {username} registered successfully")
        else:
            print(f"❌ Registration failed: {response.get('message', 'Unknown error')}")
            
        return response
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode() + CONFIG['salt']).hexdigest()
    
    def list_files(self, path=""):
        if not self.authenticated:
            print("❌ Authentication required")
            return {"status": "error", "message": "Authentication required"}
            
        request = {
            "command": "list",
            "path": path
        }
        
        response = self.send_request(request)
        
        if response.get('status') == "success":
            files = response.get('files', [])
            current_path = response.get('path', '')
            
            print(f"\n📁 Files in /{current_path}:")
            print("-" * 60)
            
            if not files:
                print("  (empty directory)")
            else:
                for item in sorted(files, key=lambda x: (not x['is_dir'], x['name'].lower())):
                    icon = "📁" if item['is_dir'] else "📄"
                    size = f"{item['size']:,} bytes" if not item['is_dir'] else "<DIR>"
                    modified = datetime.fromtimestamp(item['modified']).strftime('%Y-%m-%d %H:%M')
                    print(f"  {icon} {item['name']:<30} {size:<15} {modified}")
            print()
        else:
            print(f"❌ List failed: {response.get('message', 'Unknown error')}")
        
        return response
    
    def upload_file(self, local_path, remote_filename=None, overwrite=False):
        if not self.authenticated:
            print("❌ Authentication required")
            return {"status": "error", "message": "Authentication required"}
            
        if not os.path.exists(local_path):
            print(f"❌ Local file not found: {local_path}")
            return {"status": "error", "message": "Local file not found"}
            
        if os.path.isdir(local_path):
            print("❌ Use sync command for directories")
            return {"status": "error", "message": "Directories must be uploaded with sync"}
            
        filename = remote_filename or os.path.basename(local_path)
        filesize = os.path.getsize(local_path)
        
        print(f"📤 Uploading {local_path} -> {filename} ({filesize:,} bytes)")
        
        # Prepare upload
        request = {
            "command": "upload",
            "filename": filename,
            "filesize": filesize,
            "overwrite": overwrite
        }
        
        response = self.send_request(request)
        
        if response.get('status') != "ready":
            print(f"❌ Upload preparation failed: {response.get('message', 'Unknown error')}")
            return response
            
        session_id = response.get('session_id')
        chunk_size = response.get('chunk_size', 4000)
        
        try:
            with open(local_path, 'rb') as f:
                position = 0
                while position < filesize:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    # Encrypt chunk
                    encrypted_chunk = self.encrypt_data(chunk, self.session_key)
                    chunk_data = base64.b64encode(encrypted_chunk).decode()
                    
                    # Send chunk
                    chunk_request = {
                        "command": "upload_chunk",
                        "session_id": session_id,
                        "chunk": chunk_data,
                        "position": position
                    }
                    
                    response = self.send_request(chunk_request)
                    if response.get('status') not in ["success", "complete"]:
                        print(f"\n❌ Upload failed: {response.get('message', 'Unknown error')}")
                        return response
                        
                    position += len(chunk)
                    progress = min(100, int(position/filesize*100))
                    print(f"\rProgress: {progress}% ({position:,}/{filesize:,} bytes)", end='')
                    
                    if response.get('status') == "complete":
                        print(f"\n✅ Upload completed! Hash: {response.get('hash', '')}")
                        return {"status": "success", "message": "File uploaded successfully"}
                
                print(f"\n✅ Upload completed!")
                return {"status": "success", "message": "File uploaded successfully"}
                
        except Exception as e:
            print(f"\n❌ Upload error: {str(e)}")
            logging.error(f"Upload error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def download_file(self, remote_filename, local_path=None):
        if not self.authenticated:
            print("❌ Authentication required")
            return {"status": "error", "message": "Authentication required"}
            
        print(f"📥 Preparing download: {remote_filename}")
        
        # Prepare download
        request = {
            "command": "download",
            "filename": remote_filename
        }
        
        response = self.send_request(request)
        
        if response.get('status') != "ready":
            print(f"❌ Download preparation failed: {response.get('message', 'Unknown error')}")
            return response
            
        filename = response.get('filename')
        filesize = response.get('filesize')
        remote_hash = response.get('hash')
        chunk_size = response.get('chunk_size', 4000)
        
        local_path = local_path or os.path.join(CONFIG['download_dir'], filename)
        
        # Handle existing file
        if os.path.exists(local_path):
            base, ext = os.path.splitext(local_path)
            counter = 1
            while os.path.exists(f"{base}_{counter}{ext}"):
                counter += 1
            local_path = f"{base}_{counter}{ext}"
        
        print(f"📥 Downloading {filename} ({filesize:,} bytes) -> {local_path}")
        
        try:
            with open(local_path, 'wb') as f:
                position = 0
                while position < filesize:
                    # Request next chunk
                    chunk_request = {
                        "command": "download_chunk",
                        "filename": filename,
                        "position": position,
                        "chunk_size": chunk_size
                    }
                    
                    response = self.send_request(chunk_request)
                    if response.get('status') != "success":
                        print(f"\n❌ Download failed: {response.get('message', 'Unknown error')}")
                        try:
                            os.remove(local_path)
                        except:
                            pass
                        return response
                        
                    # Decrypt chunk
                    encrypted_chunk = base64.b64decode(response['chunk'].encode())
                    chunk = self.decrypt_data(encrypted_chunk, self.session_key)
                    
                    f.write(chunk)
                    position += len(chunk)
                    progress = min(100, int(position/filesize*100))
                    print(f"\rProgress: {progress}% ({position:,}/{filesize:,} bytes)", end='')
                
                print("\n📥 Download completed, verifying...")
                
                # Verify hash
                local_hash = self.calculate_file_hash(local_path)
                if local_hash != remote_hash:
                    os.remove(local_path)
                    print("❌ File integrity check failed!")
                    return {"status": "error", "message": "File integrity check failed"}
                
                print(f"✅ Download successful! File saved to: {local_path}")
                return {
                    "status": "success",
                    "message": "File downloaded successfully",
                    "path": local_path,
                    "hash": local_hash
                }
                
        except Exception as e:
            print(f"\n❌ Download error: {str(e)}")
            try:
                os.remove(local_path)
            except:
                pass
            logging.error(f"Download error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def delete_file(self, remote_filename):
        if not self.authenticated:
            print("❌ Authentication required")
            return {"status": "error", "message": "Authentication required"}
            
        request = {
            "command": "delete",
            "filename": remote_filename
        }
        
        response = self.send_request(request)
        
        if response.get('status') == "success":
            print(f"✅ File deleted: {remote_filename}")
        else:
            print(f"❌ Delete failed: {response.get('message', 'Unknown error')}")
            
        return response
    
    def make_directory(self, dirname):
        if not self.authenticated:
            print("❌ Authentication required")
            return {"status": "error", "message": "Authentication required"}
            
        request = {
            "command": "mkdir",
            "dirname": dirname
        }
        
        response = self.send_request(request)
        
        if response.get('status') == "success":
            print(f"✅ Directory created: {dirname}")
        else:
            print(f"❌ Create directory failed: {response.get('message', 'Unknown error')}")
            
        return response
    
    def sync_directory(self, local_dir, remote_path=""):
        if not self.authenticated:
            print("❌ Authentication required")
            return {"status": "error", "message": "Authentication required"}
            
        print(f"🔄 Synchronizing with server...")
        
        # First get server state
        request = {
            "command": "sync",
            "path": remote_path
        }
        
        response = self.send_request(request)
        if response.get('status') != "success":
            print(f"❌ Sync failed: {response.get('message', 'Unknown error')}")
            return response
            
        server_state = response.get('sync_data', {})
        
        # Create local directory structure
        os.makedirs(local_dir, exist_ok=True)
        
        # Compare and download needed files
        results = {"downloaded": [], "skipped": [], "errors": []}
        total_files = sum(len(data['files']) for data in server_state.values())
        processed = 0
        
        print(f"📊 Found {total_files} files on server")
        
        for rel_path, data in server_state.items():
            local_subdir = os.path.join(local_dir, rel_path) if rel_path else local_dir
            os.makedirs(local_subdir, exist_ok=True)
            
            # Process files
            for filename, file_info in data['files'].items():
                processed += 1
                local_file = os.path.join(local_subdir, filename)
                remote_file = os.path.join(remote_path, rel_path, filename).replace('\\', '/')
                remote_hash = file_info['hash']
                
                download_needed = True
                if os.path.exists(local_file):
                    # Check if file needs update
                    local_hash = self.calculate_file_hash(local_file)
                    if local_hash == remote_hash:
                        download_needed = False
                
                print(f"\r[{processed}/{total_files}] Processing: {filename}", end='')
                
                if download_needed:
                    result = self.download_file(remote_file, local_file)
                    if result.get('status') == "success":
                        results['downloaded'].append(filename)
                    else:
                        results['errors'].append(f"{filename}: {result.get('message', 'Unknown error')}")
                else:
                    results['skipped'].append(filename)
        
        print(f"\n✅ Synchronization complete!")
        print(f"📥 Downloaded: {len(results['downloaded'])}")
        print(f"⏭️  Skipped: {len(results['skipped'])}")
        print(f"❌ Errors: {len(results['errors'])}")
        
        if results['errors']:
            print("\nErrors:")
            for error in results['errors'][:5]:  # Show first 5 errors
                print(f"  • {error}")
            if len(results['errors']) > 5:
                print(f"  ... and {len(results['errors']) - 5} more")
        
        return {
            "status": "success",
            "message": "Synchronization complete",
            "results": results
        }
    
    def calculate_file_hash(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(65536)  # 64KB chunks
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception:
            return ""
    
    def encrypt_data(self, data, key):
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        encrypted = cipher.encrypt(data)
        return iv + encrypted
    
    def decrypt_data(self, data, key):
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(encrypted)

def interactive_mode():
    """Interactive mode for easier use"""
    print("🔐 SFTP Client - Interactive Mode")
    print("=" * 40)
    
    client = SFTP_Client()
    
    # Connect to server
    host = input(f"Server host [{CONFIG['host']}]: ").strip() or CONFIG['host']
    port_input = input(f"Server port [{CONFIG['port']}]: ").strip()
    port = int(port_input) if port_input else CONFIG['port']
    
    if not client.connect(host, port):
        return
    
    try:
        # Authentication
        while not client.authenticated:
            print("\nAuthentication required:")
            print("1. Login")
            print("2. Register")
            choice = input("Choose (1/2): ").strip()
            
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            
            if choice == "2":
                client.register(username, password)
            else:
                client.authenticate(username, password)
        
        # Main menu
        while client.connected and client.authenticated:
            print("\n📋 Available commands:")
            print("1. List files (ls)")
            print("2. Upload file (put)")
            print("3. Download file (get)")
            print("4. Delete file (rm)")
            print("5. Create directory (mkdir)")
            print("6. Sync directory (sync)")
            print("7. Quit (q)")
            
            cmd = input("\nEnter command: ").strip().lower()
            
            if cmd in ['1', 'ls', 'list']:
                path = input("Path [empty for root]: ").strip()
                client.list_files(path)
                
            elif cmd in ['2', 'put', 'upload']:
                local_path = input("Local file path: ").strip()
                remote_name = input("Remote filename [empty for same]: ").strip()
                overwrite = input("Overwrite if exists? (y/N): ").strip().lower() == 'y'
                client.upload_file(local_path, remote_name or None, overwrite)
                
            elif cmd in ['3', 'get', 'download']:
                remote_file = input("Remote filename: ").strip()
                local_path = input("Local path [empty for downloads dir]: ").strip()
                client.download_file(remote_file, local_path or None)
                
            elif cmd in ['4', 'rm', 'delete']:
                filename = input("Filename to delete: ").strip()
                if input(f"Delete '{filename}'? (y/N): ").strip().lower() == 'y':
                    client.delete_file(filename)
                    
            elif cmd in ['5', 'mkdir']:
                dirname = input("Directory name: ").strip()
                client.make_directory(dirname)
                
            elif cmd in ['6', 'sync']:
                local_dir = input("Local directory: ").strip()
                remote_path = input("Remote path [empty for root]: ").strip()
                client.sync_directory(local_dir, remote_path)
                
            elif cmd in ['7', 'q', 'quit', 'exit']:
                break
                
            else:
                print("❌ Invalid command")
    
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    finally:
        client.disconnect()

def main():
    parser = argparse.ArgumentParser(description="🔐 Secure File Transfer Protocol (SFTP) Client")
    parser.add_argument('--interactive', '-i', action='store_true', help='Start in interactive mode')
    parser.add_argument('--host', default=CONFIG['host'], help='Server host')
    parser.add_argument('--port', type=int, default=CONFIG['port'], help='Server port')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Auth commands
    auth_parser = subparsers.add_parser('auth', help='Authenticate with server')
    auth_parser.add_argument('username', help='Your username')
    
    register_parser = subparsers.add_parser('register', help='Register new user')
    register_parser.add_argument('username', help='New username')
    
    # File operations
    list_parser = subparsers.add_parser('list', help='List files on server')
    list_parser.add_argument('path', nargs='?', default='', help='Path to list')
    
    upload_parser = subparsers.add_parser('upload', help='Upload file to server')
    upload_parser.add_argument('local_path', help='Local file path')
    upload_parser.add_argument('--remote', help='Remote filename')
    upload_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing file')
    
    download_parser = subparsers.add_parser('download', help='Download file from server')
    download_parser.add_argument('remote_filename', help='Filename on server')
    download_parser.add_argument('--local', help='Local destination path')
    
    delete_parser = subparsers.add_parser('delete', help='Delete file on server')
    delete_parser.add_argument('remote_filename', help='Filename to delete')
    
    mkdir_parser = subparsers.add_parser('mkdir', help='Create directory on server')
    mkdir_parser.add_argument('dirname', help='Directory name')
    
    sync_parser = subparsers.add_parser('sync', help='Synchronize directory with server')
    sync_parser.add_argument('local_dir', help='Local directory path')
    sync_parser.add_argument('--remote', default='', help='Remote directory path')
    
    args = parser.parse_args()
    
    # If no command specified or interactive mode requested, start interactive mode
    if not args.command or args.interactive:
        interactive_mode()
        return
    
    client = SFTP_Client()
    
    try:
        # Connect to server
        if not client.connect(args.host, args.port):
            sys.exit(1)
        
        # Handle authentication commands
        if args.command in ['auth', 'register']:
            password = getpass.getpass("Password: ")
            
            if args.command == 'auth':
                result = client.authenticate(args.username, password)
            else:
                result = client.register(args.username, password)
                
            if result.get('status') != 'success':
                sys.exit(1)
                
            # If just authenticating, list files
            if args.command == 'auth':
                client.list_files()
        
        else:
            # For other commands, we need to authenticate first
            print("Authentication required:")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            
            auth_result = client.authenticate(username, password)
            if auth_result.get('status') != 'success':
                sys.exit(1)
            
            # Execute the requested command
            if args.command == 'list':
                client.list_files(args.path)
            elif args.command == 'upload':
                client.upload_file(args.local_path, args.remote, args.overwrite)
            elif args.command == 'download':
                client.download_file(args.remote_filename, args.local)
            elif args.command == 'delete':
                client.delete_file(args.remote_filename)
            elif args.command == 'mkdir':
                client.make_directory(args.dirname)
            elif args.command == 'sync':
                client.sync_directory(args.local_dir, args.remote)
    
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        logging.error(f"Client error: {str(e)}")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
