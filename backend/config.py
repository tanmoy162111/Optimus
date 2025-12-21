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
    
    # SSH connection tuning (WINDOWS OPTIMIZED) - REDUCED TIMEOUTS FOR DEBUGGING
    KALI_CONNECT_TIMEOUT = int(os.getenv('KALI_CONNECT_TIMEOUT', 15))   # Reduced from 120 to 15 seconds
    KALI_CONNECT_RETRIES = int(os.getenv('KALI_CONNECT_RETRIES', 3))    # Reduced from 10 to 3 attempts
    KALI_KEEPALIVE_SECONDS = int(os.getenv('KALI_KEEPALIVE_SECONDS', 30))  # Reduced from 60
    KALI_COMMAND_TIMEOUT = int(os.getenv('KALI_COMMAND_TIMEOUT', 300))  # Reduced from 900 to 5 minutes
    
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
    
    # Ollama LLM Configuration
    OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
    OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'codellama:7b-instruct')
    OLLAMA_TIMEOUT = int(os.getenv('OLLAMA_TIMEOUT', 120))
    OLLAMA_ENABLED = os.getenv('OLLAMA_ENABLED', 'true').lower() == 'true'
    
    # Self-Learning Parser
    PARSER_LEARNING_ENABLED = os.getenv('PARSER_LEARNING_ENABLED', 'true').lower() == 'true'
    PARSER_MIN_CONFIDENCE = float(os.getenv('PARSER_MIN_CONFIDENCE', 0.7))
    
    # Deep RL Configuration
    DEEP_RL_ENABLED = os.getenv('DEEP_RL_ENABLED', 'true').lower() == 'true'
    DEEP_RL_STATE_DIM = int(os.getenv('DEEP_RL_STATE_DIM', 128))
    DEEP_RL_NUM_ACTIONS = int(os.getenv('DEEP_RL_NUM_ACTIONS', 35))
    DEEP_RL_LEARNING_RATE = float(os.getenv('DEEP_RL_LEARNING_RATE', 0.0001))
    DEEP_RL_GAMMA = float(os.getenv('DEEP_RL_GAMMA', 0.99))
    DEEP_RL_BUFFER_SIZE = int(os.getenv('DEEP_RL_BUFFER_SIZE', 100000))
    DEEP_RL_BATCH_SIZE = int(os.getenv('DEEP_RL_BATCH_SIZE', 64))
    DEEP_RL_USE_PER = os.getenv('DEEP_RL_USE_PER', 'true').lower() == 'true'
    DEEP_RL_USE_NOISY = os.getenv('DEEP_RL_USE_NOISY', 'true').lower() == 'true'
    
    # Intelligence Configuration
    NVD_API_KEY = os.getenv('NVD_API_KEY', '')
    INTEL_CACHE_TTL = int(os.getenv('INTEL_CACHE_TTL', 3600))
    
    # Dark Web Intelligence (requires Tor)
    DARK_WEB_ENABLED = os.getenv('DARK_WEB_ENABLED', 'false').lower() == 'true'
    TOR_PROXY_HOST = os.getenv('TOR_PROXY_HOST', '127.0.0.1')
    TOR_PROXY_PORT = int(os.getenv('TOR_PROXY_PORT', 9050))
    
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