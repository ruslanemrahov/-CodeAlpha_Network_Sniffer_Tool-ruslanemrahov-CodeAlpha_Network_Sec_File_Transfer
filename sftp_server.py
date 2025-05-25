import os
import socket
import threading
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import json
import base64
import logging
from datetime import datetime
import time

# Configuration
CONFIG = {
    "host": "0.0.0.0",
    "port": 5000,
    "max_clients": 10,
    "buffer_size": 8192,
    "salt": b"salt_1234_secure_transfer",
    "auth_file": "users.auth",
    "upload_dir": "server_uploads",
    "log_file": "server.log"
}

# Set up logging
logging.basicConfig(
    filename=CONFIG['log_file'],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SFTP_Server:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}
        self.running = False
        self.upload_sessions = {}  # Track ongoing uploads
        
        # Create necessary directories
        os.makedirs(CONFIG['upload_dir'], exist_ok=True)
        
        # Create default admin user if no users exist
        self.create_default_user()
        
    def create_default_user(self):
        """Create default admin user if no users exist"""
        try:
            with open(CONFIG['auth_file'], 'r') as f:
                users = json.load(f)
            if users:
                return
        except (FileNotFoundError, json.JSONDecodeError):
            users = {}
            
        # Create default admin user
        users['admin'] = {
            "password": self.hash_password('admin123'),
            "created": datetime.now().isoformat(),
            "role": "admin"
        }
        
        with open(CONFIG['auth_file'], 'w') as f:
            json.dump(users, f, indent=2)
        
        print("Default user created: admin/admin123")
        
    def start(self):
        try:
            self.server_socket.bind((CONFIG['host'], CONFIG['port']))
            self.server_socket.listen(CONFIG['max_clients'])
            self.running = True
            logging.info(f"Server started on {CONFIG['host']}:{CONFIG['port']}")
            print(f"🚀 SFTP Server listening on {CONFIG['host']}:{CONFIG['port']}")
            print(f"📁 Upload directory: {os.path.abspath(CONFIG['upload_dir'])}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.error:
                    if self.running:
                        continue
                    else:
                        break
        except Exception as e:
            logging.error(f"Server error: {str(e)}")
            print(f"❌ Server error: {str(e)}")
        finally:
            self.stop()
    
    def stop(self):
        self.running = False
        for client in list(self.clients.values()):
            try:
                client['socket'].close()
            except:
                pass
        try:
            self.server_socket.close()
        except:
            pass
        logging.info("Server stopped")
        print("🛑 Server stopped")
    
    def handle_client(self, client_socket, client_address):
        client_id = f"{client_address[0]}:{client_address[1]}"
        self.clients[client_id] = {
            "socket": client_socket,
            "address": client_address,
            "authenticated": False,
            "key": None,
            "username": None
        }
        
        try:
            logging.info(f"New connection from {client_id}")
            print(f"🔗 New connection from {client_id}")
            
            while self.running:
                try:
                    client_socket.settimeout(30.0)  # 30 second timeout
                    data = client_socket.recv(CONFIG['buffer_size'])
                    if not data:
                        break
                        
                    try:
                        request = json.loads(data.decode('utf-8'))
                        response = self.process_request(request, client_id)
                        
                        response_data = json.dumps(response).encode('utf-8')
                        client_socket.send(response_data)
                        
                    except json.JSONDecodeError:
                        error_msg = {"status": "error", "message": "Invalid JSON format"}
                        client_socket.send(json.dumps(error_msg).encode('utf-8'))
                    except UnicodeDecodeError:
                        error_msg = {"status": "error", "message": "Invalid character encoding"}
                        client_socket.send(json.dumps(error_msg).encode('utf-8'))
                        
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break
                except Exception as e:
                    logging.error(f"Client {client_id} handling error: {str(e)}")
                    break
                
        except Exception as e:
            logging.error(f"Client {client_id} error: {str(e)}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            if client_id in self.clients:
                del self.clients[client_id]
            logging.info(f"Client {client_id} disconnected")
            print(f"🔌 Client {client_id} disconnected")
    
    def process_request(self, request, client_id):
        if not request.get('command'):
            return {"status": "error", "message": "No command specified"}
            
        command = request['command']
        
        # Commands that don't require authentication
        if command in ['auth', 'register']:
            if command == "auth":
                return self.authenticate(request, client_id)
            elif command == "register":
                return self.register_user(request)
        
        # Check authentication for other commands
        if not self.clients[client_id]['authenticated']:
            return {"status": "error", "message": "Authentication required"}
        
        # Authenticated commands
        if command == "list":
            return self.list_files(request)
        elif command == "upload":
            return self.prepare_upload(request, client_id)
        elif command == "upload_chunk":
            return self.receive_upload_chunk(request, client_id)
        elif command == "download":
            return self.prepare_download(request, client_id)
        elif command == "download_chunk":
            return self.send_download_chunk(request, client_id)
        elif command == "delete":
            return self.delete_file(request)
        elif command == "sync":
            return self.sync_directory(request)
        elif command == "mkdir":
            return self.make_directory(request)
        else:
            return {"status": "error", "message": f"Unknown command: {command}"}
    
    def authenticate(self, request, client_id):
        username = request.get('username')
        password = request.get('password')
        
        if not username or not password:
            return {"status": "error", "message": "Username and password required"}
            
        try:
            with open(CONFIG['auth_file'], 'r') as f:
                users = json.load(f)
                
            if username in users and users[username]['password'] == password:
                # Generate session key
                key = PBKDF2(password.encode(), CONFIG['salt'], dkLen=32)
                self.clients[client_id]['key'] = key
                self.clients[client_id]['authenticated'] = True
                self.clients[client_id]['username'] = username
                
                logging.info(f"User {username} authenticated from {client_id}")
                print(f"✅ User {username} authenticated from {client_id}")
                
                return {
                    "status": "success", 
                    "message": "Authentication successful",
                    "username": username
                }
            else:
                logging.warning(f"Failed authentication attempt for {username} from {client_id}")
                return {"status": "error", "message": "Invalid credentials"}
                
        except FileNotFoundError:
            return {"status": "error", "message": "User database not found"}
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return {"status": "error", "message": "Authentication system error"}
    
    def register_user(self, request):
        username = request.get('username')
        password = request.get('password')
        
        if not username or not password:
            return {"status": "error", "message": "Username and password required"}
            
        if len(username) < 3:
            return {"status": "error", "message": "Username must be at least 3 characters"}
        
        if len(password) < 6:
            return {"status": "error", "message": "Password must be at least 6 characters"}
            
        try:
            # Load existing users or create new file
            try:
                with open(CONFIG['auth_file'], 'r') as f:
                    users = json.load(f)
            except FileNotFoundError:
                users = {}
                
            if username in users:
                return {"status": "error", "message": "Username already exists"}
                
            users[username] = {
                "password": self.hash_password(password),
                "created": datetime.now().isoformat(),
                "role": "user"
            }
            
            with open(CONFIG['auth_file'], 'w') as f:
                json.dump(users, f, indent=2)
                
            logging.info(f"New user registered: {username}")
            print(f"👤 New user registered: {username}")
            
            return {"status": "success", "message": "User registered successfully"}
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            return {"status": "error", "message": "Registration failed"}
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode() + CONFIG['salt']).hexdigest()
    
    def list_files(self, request):
        path = request.get('path', '')
        # Sanitize path to prevent directory traversal
        path = path.replace('..', '').replace('//', '/').strip('/')
        full_path = os.path.join(CONFIG['upload_dir'], path)
        
        try:
            if not os.path.exists(full_path):
                return {"status": "error", "message": "Path does not exist"}
                
            items = []
            for item in os.listdir(full_path):
                item_path = os.path.join(full_path, item)
                try:
                    stat_info = os.stat(item_path)
                    items.append({
                        "name": item,
                        "is_dir": os.path.isdir(item_path),
                        "size": stat_info.st_size if not os.path.isdir(item_path) else 0,
                        "modified": stat_info.st_mtime,
                        "permissions": oct(stat_info.st_mode)[-3:]
                    })
                except OSError:
                    # Skip files we can't access
                    continue
                
            return {"status": "success", "files": items, "path": path}
        except Exception as e:
            logging.error(f"List files error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def prepare_upload(self, request, client_id):
        filename = request.get('filename')
        filesize = request.get('filesize')
        overwrite = request.get('overwrite', False)
        
        if not filename or filesize is None:
            return {"status": "error", "message": "Filename and filesize required"}
            
        # Sanitize filename
        filename = os.path.basename(filename)
        if not filename or filename.startswith('.'):
            return {"status": "error", "message": "Invalid filename"}
            
        filepath = os.path.join(CONFIG['upload_dir'], filename)
        
        if os.path.exists(filepath) and not overwrite:
            return {"status": "error", "message": "File already exists", "code": "FILE_EXISTS"}
            
        # Check available space
        try:
            stat = os.statvfs(CONFIG['upload_dir'])
            free_space = stat.f_frsize * stat.f_bavail
            if free_space < filesize:
                return {"status": "error", "message": "Insufficient disk space"}
        except AttributeError:
            # Windows doesn't have statvfs
            import shutil
            free_space = shutil.disk_usage(CONFIG['upload_dir']).free
            if free_space < filesize:
                return {"status": "error", "message": "Insufficient disk space"}
        except Exception:
            pass  # Skip space check if not supported
            
        # Initialize upload session
        session_id = f"{client_id}_{filename}_{int(time.time())}"
        self.upload_sessions[session_id] = {
            "filename": filename,
            "filepath": filepath,
            "filesize": filesize,
            "received": 0,
            "file_handle": None,
            "hash": hashlib.sha256(),
            "client_id": client_id
        }
        
        try:
            self.upload_sessions[session_id]["file_handle"] = open(filepath, 'wb')
        except Exception as e:
            del self.upload_sessions[session_id]
            return {"status": "error", "message": f"Cannot create file: {str(e)}"}
        
        return {
            "status": "ready",
            "message": "Ready to receive file",
            "session_id": session_id,
            "chunk_size": CONFIG['buffer_size'] - 1024  # Leave room for metadata
        }
    
    def receive_upload_chunk(self, request, client_id):
        session_id = request.get('session_id')
        chunk_data = request.get('chunk')
        position = request.get('position', 0)
        
        if not session_id or session_id not in self.upload_sessions:
            return {"status": "error", "message": "Invalid upload session"}
            
        session = self.upload_sessions[session_id]
        
        if session['client_id'] != client_id:
            return {"status": "error", "message": "Session does not belong to this client"}
            
        try:
            # Decrypt chunk if encrypted
            if self.clients[client_id]['key']:
                encrypted_chunk = base64.b64decode(chunk_data.encode())
                chunk = self.decrypt_data(encrypted_chunk, self.clients[client_id]['key'])
            else:
                chunk = base64.b64decode(chunk_data.encode())
            
            # Write chunk to file
            session['file_handle'].seek(position)
            session['file_handle'].write(chunk)
            session['file_handle'].flush()
            
            session['received'] += len(chunk)
            session['hash'].update(chunk)
            
            # Check if upload is complete
            if session['received'] >= session['filesize']:
                session['file_handle'].close()
                file_hash = session['hash'].hexdigest()
                
                logging.info(f"File upload completed: {session['filename']} by {self.clients[client_id]['username']}")
                print(f"📁 File uploaded: {session['filename']} by {self.clients[client_id]['username']}")
                
                # Clean up session
                del self.upload_sessions[session_id]
                
                return {
                    "status": "complete",
                    "message": "File upload completed",
                    "hash": file_hash
                }
            else:
                return {
                    "status": "success",
                    "message": "Chunk received",
                    "received": session['received'],
                    "total": session['filesize']
                }
                
        except Exception as e:
            # Clean up on error
            if session['file_handle']:
                session['file_handle'].close()
            try:
                os.remove(session['filepath'])
            except:
                pass
            del self.upload_sessions[session_id]
            
            logging.error(f"Upload chunk error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def prepare_download(self, request, client_id):
        filename = request.get('filename')
        if not filename:
            return {"status": "error", "message": "Filename required"}
            
        # Sanitize filename
        filename = filename.replace('..', '').replace('//', '/')
        filepath = os.path.join(CONFIG['upload_dir'], filename)
        
        if not os.path.exists(filepath):
            return {"status": "error", "message": "File not found"}
            
        if os.path.isdir(filepath):
            return {"status": "error", "message": "Cannot download directories directly"}
            
        try:
            filesize = os.path.getsize(filepath)
            file_hash = self.calculate_file_hash(filepath)
            
            return {
                "status": "ready",
                "message": "Ready to send file",
                "filename": os.path.basename(filename),
                "filesize": filesize,
                "hash": file_hash,
                "chunk_size": CONFIG['buffer_size'] - 1024
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def send_download_chunk(self, request, client_id):
        filename = request.get('filename')
        position = request.get('position', 0)
        chunk_size = request.get('chunk_size', CONFIG['buffer_size'] - 1024)
        
        if not filename:
            return {"status": "error", "message": "Filename required"}
            
        filepath = os.path.join(CONFIG['upload_dir'], filename)
        
        if not os.path.exists(filepath):
            return {"status": "error", "message": "File not found"}
            
        try:
            with open(filepath, 'rb') as f:
                f.seek(position)
                chunk = f.read(chunk_size)
                
                if not chunk:
                    return {"status": "error", "message": "No data at position"}
                
                # Encrypt chunk if client has key
                if self.clients[client_id]['key']:
                    encrypted_chunk = self.encrypt_data(chunk, self.clients[client_id]['key'])
                    chunk_data = base64.b64encode(encrypted_chunk).decode()
                else:
                    chunk_data = base64.b64encode(chunk).decode()
                
                return {
                    "status": "success",
                    "chunk": chunk_data,
                    "size": len(chunk)
                }
                
        except Exception as e:
            logging.error(f"Download chunk error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def delete_file(self, request):
        filename = request.get('filename')
        if not filename:
            return {"status": "error", "message": "Filename required"}
            
        # Sanitize filename
        filename = filename.replace('..', '').replace('//', '/')
        filepath = os.path.join(CONFIG['upload_dir'], filename)
        
        try:
            if os.path.exists(filepath):
                if os.path.isdir(filepath):
                    os.rmdir(filepath)  # Only remove empty directories
                else:
                    os.remove(filepath)
                
                logging.info(f"File deleted: {filename}")
                return {"status": "success", "message": "File deleted"}
            else:
                return {"status": "error", "message": "File not found"}
        except OSError as e:
            if e.errno == 39:  # Directory not empty
                return {"status": "error", "message": "Directory not empty"}
            return {"status": "error", "message": str(e)}
        except Exception as e:
            logging.error(f"Delete error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def make_directory(self, request):
        dirname = request.get('dirname')
        if not dirname:
            return {"status": "error", "message": "Directory name required"}
            
        # Sanitize dirname
        dirname = dirname.replace('..', '').replace('//', '/').strip('/')
        dirpath = os.path.join(CONFIG['upload_dir'], dirname)
        
        try:
            os.makedirs(dirpath, exist_ok=True)
            logging.info(f"Directory created: {dirname}")
            return {"status": "success", "message": "Directory created"}
        except Exception as e:
            logging.error(f"Create directory error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def sync_directory(self, request):
        path = request.get('path', '')
        # Sanitize path
        path = path.replace('..', '').replace('//', '/').strip('/')
        full_path = os.path.join(CONFIG['upload_dir'], path)
        
        try:
            if not os.path.exists(full_path):
                return {"status": "error", "message": "Path does not exist"}
                
            sync_data = {}
            for root, dirs, files in os.walk(full_path):
                rel_path = os.path.relpath(root, full_path)
                if rel_path == '.':
                    rel_path = ''
                    
                sync_data[rel_path] = {
                    "files": {},
                    "dirs": dirs
                }
                
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(file_path)
                        sync_data[rel_path]["files"][file] = {
                            "size": stat_info.st_size,
                            "modified": stat_info.st_mtime,
                            "hash": self.calculate_file_hash(file_path)
                        }
                    except OSError:
                        # Skip files we can't access
                        continue
                    
            return {"status": "success", "sync_data": sync_data}
        except Exception as e:
            logging.error(f"Sync error: {str(e)}")
            return {"status": "error", "message": str(e)}
    
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

def main():
    print("🔐 Secure File Transfer Protocol (SFTP) Server")
    print("=" * 50)
    
    server = SFTP_Server()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down server...")
        server.stop()
    except Exception as e:
        print(f"❌ Server error: {e}")
        server.stop()

if __name__ == "__main__":
    main()
