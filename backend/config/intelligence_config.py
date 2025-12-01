import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class IntelligenceConfig:
    """Configuration for the intelligence module"""
    
    # Feature toggles
    enable_memory: bool = True
    enable_web_intel: bool = True
    enable_delegation: bool = True
    enable_adaptive: bool = True
    enable_chaining: bool = True
    enable_explainable: bool = True
    enable_learning: bool = True
    enable_zeroday: bool = True
    enable_campaign: bool = True
    
    # Database paths
    memory_db_path: str = "data/optimus_memory.db"
    learning_model_path: str = "data/models"
    
    # API Keys (from environment)
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    censys_api_key: Optional[str] = None
    
    # Learning parameters
    learning_rate: float = 0.01
    memory_consolidation_days: int = 30
    
    # Adaptive exploitation
    max_retries: int = 3
    base_backoff_seconds: int = 2
    
    # LLM Configuration (optional)
    llm_provider: Optional[str] = None  # 'anthropic', 'openai', None
    llm_api_key: Optional[str] = None
    llm_model: str = "claude-3-sonnet-20240229"
    
    @classmethod
    def from_env(cls):
        """Load configuration from environment variables"""
        return cls(
            enable_memory=os.getenv('OPTIMUS_ENABLE_MEMORY', 'true').lower() == 'true',
            enable_web_intel=os.getenv('OPTIMUS_ENABLE_WEB_INTEL', 'true').lower() == 'true',
            enable_delegation=os.getenv('OPTIMUS_ENABLE_DELEGATION', 'true').lower() == 'true',
            enable_adaptive=os.getenv('OPTIMUS_ENABLE_ADAPTIVE', 'true').lower() == 'true',
            enable_chaining=os.getenv('OPTIMUS_ENABLE_CHAINING', 'true').lower() == 'true',
            enable_explainable=os.getenv('OPTIMUS_ENABLE_EXPLAINABLE', 'true').lower() == 'true',
            enable_learning=os.getenv('OPTIMUS_ENABLE_LEARNING', 'true').lower() == 'true',
            enable_zeroday=os.getenv('OPTIMUS_ENABLE_ZERODAY', 'true').lower() == 'true',
            enable_campaign=os.getenv('OPTIMUS_ENABLE_CAMPAIGN', 'true').lower() == 'true',
            memory_db_path=os.getenv('OPTIMUS_MEMORY_DB', 'data/optimus_memory.db'),
            shodan_api_key=os.getenv('SHODAN_API_KEY'),
            virustotal_api_key=os.getenv('VIRUSTOTAL_API_KEY'),
            censys_api_key=os.getenv('CENSYS_API_KEY'),
            llm_provider=os.getenv('LLM_PROVIDER'),
            llm_api_key=os.getenv('LLM_API_KEY'),
            llm_model=os.getenv('LLM_MODEL', 'claude-3-sonnet-20240229')
        )
