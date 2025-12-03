import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
    
    # Kali VM
    KALI_HOST = os.getenv('KALI_HOST', '127.0.0.1')
    KALI_PORT = int(os.getenv('KALI_PORT', 2222))
    KALI_USER = os.getenv('KALI_USER', 'kali')
    KALI_PASSWORD = os.getenv('KALI_PASSWORD', 'kali')
    KALI_KEY_PATH = os.getenv('KALI_KEY_PATH', '')
    
    # SSH connection tuning (WINDOWS OPTIMIZED)
    KALI_CONNECT_TIMEOUT = int(os.getenv('KALI_CONNECT_TIMEOUT', 60))  # Increased from 30
    KALI_CONNECT_RETRIES = int(os.getenv('KALI_CONNECT_RETRIES', 5))   # Increased from 3
    KALI_KEEPALIVE_SECONDS = int(os.getenv('KALI_KEEPALIVE_SECONDS', 30))
    KALI_COMMAND_TIMEOUT = int(os.getenv('KALI_COMMAND_TIMEOUT', 600))  # 10 minutes for long scans
    
    # Kali VM Config Dict
    KALI_VM = {
        'host': KALI_HOST,
        'port': KALI_PORT,
        'username': KALI_USER,
        'password': KALI_PASSWORD,
        'key_path': KALI_KEY_PATH,
        'connect_timeout': KALI_CONNECT_TIMEOUT,
        'connect_retries': KALI_CONNECT_RETRIES,
        'keepalive_seconds': KALI_KEEPALIVE_SECONDS
    }
    
    # Paths
    DATASET_PATH = os.getenv('DATASET_PATH', './datasets')
    MODEL_PATH = os.getenv('MODEL_PATH', './models')
    DATA_PATH = './data'
    
    # Training
    TRAINING_ENABLED = os.getenv('TRAINING_ENABLED', 'true').lower() == 'true'
    RL_EPSILON_START = float(os.getenv('RL_EPSILON_START', 1.0))
    RL_EPSILON_DECAY = float(os.getenv('RL_EPSILON_DECAY', 0.995))
    RL_EPSILON_MIN = float(os.getenv('RL_EPSILON_MIN', 0.05))
    
    # Pentesting Phases
    PHASES = [
        'reconnaissance',
        'scanning',
        'exploitation',
        'post_exploitation',
        'covering_tracks'
    ]
    
    # Tool Database
    TOOLS_BY_PHASE = {
        'reconnaissance': {
            'passive': ['sublist3r', 'theHarvester', 'shodan', 'crt.sh', 'builtwith'],
            'active': ['dnsenum', 'fierce', 'whatweb', 'traceroute']
        },
        'scanning': {
            'host_discovery': ['nmap', 'masscan'],
            'port_scanning': ['nmap', 'unicornscan'],
            'vulnerability_scanning': ['nuclei', 'nikto', 'nessus'],
            'service_enumeration': ['nmap', 'enum4linux', 'smbclient']
        },
        'exploitation': {
            'web': ['sqlmap', 'dalfox', 'commix', 'xsser'],
            'network': ['metasploit', 'exploit-db'],
            'authentication': ['hydra', 'medusa', 'hashcat']
        },
        'post_exploitation': {
            'privilege_escalation': ['linpeas', 'winpeas', 'linenum'],
            'credential_dumping': ['mimikatz', 'lazagne', 'secretsdump'],
            'persistence': ['ssh_key', 'cron_job', 'registry_run'],
            'lateral_movement': ['crackmapexec', 'psexec', 'wmiexec']
        },
        'covering_tracks': {
            'log_cleanup': ['clear_logs', 'wevtutil', 'shred'],
            'timestamp_modification': ['touch', 'timestomp'],
            'artifact_removal': ['secure_delete', 'wipe']
        }
    }