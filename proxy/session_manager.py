"""
Session Management for Proxy
Tracks client sessions, crypto methods, and server connections
"""
import threading
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class SessionStatus(Enum):
    """Session status enumeration"""
    HANDSHAKE = "handshake"
    ACTIVE = "active"
    CLOSED = "closed"
    ERROR = "error"


@dataclass
class ClientSession:
    """Represents a client session"""
    node_id: Optional[int]
    client_addr: Tuple[str, int]
    crypto_method: str
    crypto_engine: object
    proxy_pub_key: bytes
    proxy_sec_key: bytes
    client_pub_key: bytes
    status: SessionStatus
    created_at: float
    last_activity: float
    server_connection: Optional[object] = None
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def is_alive(self, timeout=300):
        """Check if session is still alive (within timeout)"""
        return (time.time() - self.last_activity) < timeout


class SessionManager:
    """Manages all client sessions"""
    
    def __init__(self):
        self.sessions: Dict[int, ClientSession] = {}
        self.lock = threading.Lock()
        self.next_client_id = 1
    
    def create_session(self, client_addr: Tuple[str, int], crypto_method: str, 
                      crypto_engine: object, proxy_pub_key: bytes, 
                      proxy_sec_key: bytes, client_pub_key: bytes,
                      node_id: Optional[int] = None) -> int:
        """Create a new client session"""
        with self.lock:
            client_id = self.next_client_id
            self.next_client_id += 1
            
            session = ClientSession(
                node_id=node_id,
                client_addr=client_addr,
                crypto_method=crypto_method,
                crypto_engine=crypto_engine,
                proxy_pub_key=proxy_pub_key,
                proxy_sec_key=proxy_sec_key,
                client_pub_key=client_pub_key,
                status=SessionStatus.HANDSHAKE,
                created_at=time.time(),
                last_activity=time.time()
            )
            
            self.sessions[client_id] = session
            return client_id
    
    def get_session(self, client_id: int) -> Optional[ClientSession]:
        """Get session by client ID"""
        with self.lock:
            return self.sessions.get(client_id)
    
    def update_session_status(self, client_id: int, status: SessionStatus):
        """Update session status"""
        with self.lock:
            if client_id in self.sessions:
                self.sessions[client_id].status = status
                self.sessions[client_id].update_activity()
    
    def remove_session(self, client_id: int):
        """Remove a session"""
        with self.lock:
            if client_id in self.sessions:
                del self.sessions[client_id]
    
    def cleanup_stale_sessions(self, timeout=300):
        """Remove stale sessions that haven't been active"""
        with self.lock:
            current_time = time.time()
            stale_ids = [
                client_id for client_id, session in self.sessions.items()
                if (current_time - session.last_activity) > timeout
            ]
            for client_id in stale_ids:
                del self.sessions[client_id]
            return len(stale_ids)
    
    def get_active_sessions_count(self) -> int:
        """Get count of active sessions"""
        with self.lock:
            return len([s for s in self.sessions.values() 
                       if s.status == SessionStatus.ACTIVE])
    
    def list_sessions(self) -> Dict[int, dict]:
        """List all sessions with their info"""
        with self.lock:
            return {
                client_id: {
                    "client_id": session.client_id,
                    "address": session.client_addr,
                    "crypto": session.crypto_method,
                    "status": session.status.value,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity
                }
                for client_id, session in self.sessions.items()
            }

