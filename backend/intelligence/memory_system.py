"""
Smart Memory System - Persistent Long-Term Memory for Optimus
Stores research results, successful approaches, and learnings across scans

Features:
- Vector embeddings for semantic search
- Cross-scan pattern recognition
- Success/failure correlation storage
- Target profile memory
- Attack chain memory
"""

import os
import json
import sqlite3
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """A single memory entry"""
    id: str
    memory_type: str  # 'attack_pattern', 'target_profile', 'tool_success', 'vuln_chain', 'technique'
    content: Dict[str, Any]
    embedding: Optional[List[float]]  # Vector embedding for semantic search
    importance: float  # 0.0 to 1.0
    access_count: int
    created_at: str
    last_accessed: str
    tags: List[str]
    related_memories: List[str]  # IDs of related memories


class SmartMemorySystem:
    """
    Persistent memory system that learns and remembers across scans.
    
    Memory Types:
    1. Attack Patterns - What attack sequences work on what targets
    2. Target Profiles - Characteristics of targets we've seen
    3. Tool Effectiveness - Which tools work best in which contexts
    4. Vulnerability Chains - Successful exploit chains
    5. Techniques - Novel techniques discovered
    6. Failures - What didn't work and why (equally important)
    """
    
    def __init__(self, db_path: str = "data/optimus_memory.db"):
        self.db_path = db_path
        self._ensure_db_exists()
        self._init_database()
        
        # In-memory caches for fast access
        self._pattern_cache = {}
        self._target_cache = {}
        self._tool_stats_cache = {}
        
        # Embedding model (using simple TF-IDF for now, can upgrade to sentence-transformers)
        self._embedding_dim = 256
        self._word_vectors = {}  # Simple word vectors
        
        logger.info(f"Smart Memory System initialized with DB: {db_path}")
    
    def _ensure_db_exists(self):
        """Ensure database directory exists"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def _init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main memories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                memory_type TEXT NOT NULL,
                content TEXT NOT NULL,
                embedding BLOB,
                importance REAL DEFAULT 0.5,
                access_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_accessed TEXT NOT NULL,
                tags TEXT,
                related_memories TEXT
            )
        ''')
        
        # Attack patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id TEXT PRIMARY KEY,
                target_type TEXT,
                technology_stack TEXT,
                attack_sequence TEXT NOT NULL,
                success_rate REAL,
                avg_time_seconds REAL,
                findings_count INTEGER,
                last_used TEXT,
                use_count INTEGER DEFAULT 0
            )
        ''')
        
        # Target profiles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_profiles (
                id TEXT PRIMARY KEY,
                target_hash TEXT UNIQUE,
                target_type TEXT,
                technologies TEXT,
                open_ports TEXT,
                vulnerabilities_found TEXT,
                successful_tools TEXT,
                failed_tools TEXT,
                waf_detected INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                scan_count INTEGER DEFAULT 0
            )
        ''')
        
        # Tool effectiveness table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tool_effectiveness (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT NOT NULL,
                target_type TEXT,
                phase TEXT,
                context_hash TEXT,
                success INTEGER,
                vulns_found INTEGER,
                execution_time REAL,
                timestamp TEXT
            )
        ''')
        
        # Vulnerability chains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vuln_chains (
                id TEXT PRIMARY KEY,
                chain_steps TEXT NOT NULL,
                initial_vuln TEXT,
                final_impact TEXT,
                success INTEGER,
                target_type TEXT,
                technology_stack TEXT,
                discovery_date TEXT,
                use_count INTEGER DEFAULT 0
            )
        ''')
        
        # Scan history for cross-scan learning
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                target TEXT,
                target_hash TEXT,
                start_time TEXT,
                end_time TEXT,
                findings_count INTEGER,
                critical_count INTEGER,
                tools_used TEXT,
                phases_completed TEXT,
                success_score REAL
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(memory_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_memories_importance ON memories(importance)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_patterns_target ON attack_patterns(target_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tool_effectiveness_tool ON tool_effectiveness(tool_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_target_profiles_hash ON target_profiles(target_hash)')
        
        conn.commit()
        conn.close()
        
        logger.info("Memory database initialized")
    
    # ==================== MEMORY STORAGE ====================
    
    def store_memory(self, memory_type: str, content: Dict[str, Any], 
                    tags: List[str] = None, importance: float = 0.5) -> str:
        """
        Store a new memory with optional embedding
        
        Args:
            memory_type: Type of memory ('attack_pattern', 'target_profile', etc.)
            content: Memory content as dictionary
            tags: Optional tags for categorization
            importance: Importance score (0.0 to 1.0)
            
        Returns:
            Memory ID
        """
        memory_id = self._generate_id(content)
        now = datetime.now().isoformat()
        
        # Generate embedding for semantic search
        text_content = self._content_to_text(content)
        embedding = self._generate_embedding(text_content)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO memories 
                (id, memory_type, content, embedding, importance, access_count, 
                 created_at, last_accessed, tags, related_memories)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            ''', (
                memory_id,
                memory_type,
                json.dumps(content),
                embedding.tobytes() if embedding is not None else None,
                importance,
                now,
                now,
                json.dumps(tags or []),
                json.dumps([])
            ))
            
            conn.commit()
            logger.debug(f"Stored memory: {memory_id} ({memory_type})")
            
        except Exception as e:
            logger.error(f"Error storing memory: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
        
        return memory_id
    
    def recall_memories(self, query: str = None, memory_type: str = None,
                       tags: List[str] = None, limit: int = 10,
                       min_importance: float = 0.0) -> List[MemoryEntry]:
        """
        Recall memories based on query, type, or tags
        
        Args:
            query: Semantic search query
            memory_type: Filter by memory type
            tags: Filter by tags
            limit: Maximum number of results
            min_importance: Minimum importance threshold
            
        Returns:
            List of matching memory entries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Build query
            sql = "SELECT * FROM memories WHERE importance >= ?"
            params = [min_importance]
            
            if memory_type:
                sql += " AND memory_type = ?"
                params.append(memory_type)
            
            if tags:
                for tag in tags:
                    sql += " AND tags LIKE ?"
                    params.append(f'%"{tag}"%')
            
            sql += " ORDER BY importance DESC, access_count DESC LIMIT ?"
            params.append(limit * 3 if query else limit)  # Get more if we need to re-rank
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            
            memories = []
            for row in rows:
                memory = MemoryEntry(
                    id=row[0],
                    memory_type=row[1],
                    content=json.loads(row[2]),
                    embedding=np.frombuffer(row[3], dtype=np.float32) if row[3] else None,
                    importance=row[4],
                    access_count=row[5],
                    created_at=row[6],
                    last_accessed=row[7],
                    tags=json.loads(row[8]) if row[8] else [],
                    related_memories=json.loads(row[9]) if row[9] else []
                )
                memories.append(memory)
            
            # If query provided, re-rank by semantic similarity
            if query and memories:
                query_embedding = self._generate_embedding(query)
                if query_embedding is not None:
                    memories = self._rank_by_similarity(memories, query_embedding)
            
            # Update access counts for returned memories
            now = datetime.now().isoformat()
            for memory in memories[:limit]:
                cursor.execute('''
                    UPDATE memories 
                    SET access_count = access_count + 1, last_accessed = ?
                    WHERE id = ?
                ''', (now, memory.id))
            
            conn.commit()
            
            return memories[:limit]
            
        except Exception as e:
            logger.error(f"Error recalling memories: {e}")
            return []
        finally:
            conn.close()
    
    # ==================== ATTACK PATTERNS ====================
    
    def store_attack_pattern(self, target_type: str, technology_stack: List[str],
                            attack_sequence: List[Dict], success: bool,
                            execution_time: float, findings: List[Dict]) -> str:
        """
        Store a successful (or failed) attack pattern
        
        Args:
            target_type: Type of target (web, api, network, cloud)
            technology_stack: Technologies detected
            attack_sequence: Sequence of tools/actions taken
            success: Whether the attack was successful
            execution_time: Total execution time
            findings: Vulnerabilities found
        """
        pattern_id = self._generate_id({
            'target_type': target_type,
            'tech': technology_stack,
            'sequence': attack_sequence
        })
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if pattern exists
            cursor.execute('SELECT * FROM attack_patterns WHERE id = ?', (pattern_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing pattern
                old_success_rate = existing[4] or 0
                old_use_count = existing[8] or 0
                new_success_rate = ((old_success_rate * old_use_count) + (1 if success else 0)) / (old_use_count + 1)
                
                cursor.execute('''
                    UPDATE attack_patterns 
                    SET success_rate = ?, avg_time_seconds = ?, findings_count = ?,
                        last_used = ?, use_count = ?
                    WHERE id = ?
                ''', (
                    new_success_rate,
                    (existing[5] + execution_time) / 2,  # Running average
                    existing[6] + len(findings),
                    datetime.now().isoformat(),
                    old_use_count + 1,
                    pattern_id
                ))
            else:
                # Insert new pattern
                cursor.execute('''
                    INSERT INTO attack_patterns 
                    (id, target_type, technology_stack, attack_sequence, success_rate,
                     avg_time_seconds, findings_count, last_used, use_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    pattern_id,
                    target_type,
                    json.dumps(technology_stack),
                    json.dumps(attack_sequence),
                    1.0 if success else 0.0,
                    execution_time,
                    len(findings),
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            logger.info(f"Stored attack pattern: {pattern_id} (success={success})")
            
            # Also store as general memory
            self.store_memory(
                memory_type='attack_pattern',
                content={
                    'target_type': target_type,
                    'technology_stack': technology_stack,
                    'attack_sequence': attack_sequence,
                    'success': success,
                    'findings_count': len(findings)
                },
                tags=[target_type] + technology_stack,
                importance=0.8 if success and findings else 0.4
            )
            
            return pattern_id
            
        except Exception as e:
            logger.error(f"Error storing attack pattern: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def get_best_attack_patterns(self, target_type: str, 
                                 technologies: List[str] = None,
                                 limit: int = 5) -> List[Dict]:
        """
        Get the best attack patterns for a given target type
        
        Args:
            target_type: Type of target
            technologies: Optional technology stack filter
            limit: Maximum patterns to return
            
        Returns:
            List of attack patterns sorted by success rate
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            sql = '''
                SELECT * FROM attack_patterns 
                WHERE target_type = ? AND use_count >= 2
                ORDER BY success_rate DESC, findings_count DESC
                LIMIT ?
            '''
            cursor.execute(sql, (target_type, limit * 2))
            rows = cursor.fetchall()
            
            patterns = []
            for row in rows:
                tech_stack = json.loads(row[2]) if row[2] else []
                
                # Filter by technology if provided
                if technologies:
                    match_score = len(set(tech_stack) & set(technologies))
                    if match_score == 0:
                        continue
                
                patterns.append({
                    'id': row[0],
                    'target_type': row[1],
                    'technology_stack': tech_stack,
                    'attack_sequence': json.loads(row[3]) if row[3] else [],
                    'success_rate': row[4],
                    'avg_time_seconds': row[5],
                    'findings_count': row[6],
                    'use_count': row[8]
                })
            
            return patterns[:limit]
            
        except Exception as e:
            logger.error(f"Error getting attack patterns: {e}")
            return []
        finally:
            conn.close()
    
    # ==================== TARGET PROFILES ====================
    
    def store_target_profile(self, target: str, profile: Dict[str, Any]) -> str:
        """
        Store or update a target profile
        
        Args:
            target: Target URL/IP
            profile: Target profile data
        """
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
        now = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if profile exists
            cursor.execute('SELECT * FROM target_profiles WHERE target_hash = ?', (target_hash,))
            existing = cursor.fetchone()
            
            if existing:
                # Merge with existing profile
                old_vulns = json.loads(existing[5]) if existing[5] else []
                old_successful_tools = json.loads(existing[6]) if existing[6] else []
                old_failed_tools = json.loads(existing[7]) if existing[7] else []
                
                new_vulns = list(set(old_vulns + profile.get('vulnerabilities', [])))
                new_successful = list(set(old_successful_tools + profile.get('successful_tools', [])))
                new_failed = list(set(old_failed_tools + profile.get('failed_tools', [])))
                
                cursor.execute('''
                    UPDATE target_profiles 
                    SET technologies = ?, open_ports = ?, vulnerabilities_found = ?,
                        successful_tools = ?, failed_tools = ?, waf_detected = ?,
                        last_seen = ?, scan_count = scan_count + 1
                    WHERE target_hash = ?
                ''', (
                    json.dumps(profile.get('technologies', [])),
                    json.dumps(profile.get('open_ports', [])),
                    json.dumps(new_vulns),
                    json.dumps(new_successful),
                    json.dumps(new_failed),
                    1 if profile.get('waf_detected') else 0,
                    now,
                    target_hash
                ))
            else:
                # Insert new profile
                cursor.execute('''
                    INSERT INTO target_profiles 
                    (id, target_hash, target_type, technologies, open_ports,
                     vulnerabilities_found, successful_tools, failed_tools,
                     waf_detected, first_seen, last_seen, scan_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    self._generate_id(profile),
                    target_hash,
                    profile.get('target_type', 'unknown'),
                    json.dumps(profile.get('technologies', [])),
                    json.dumps(profile.get('open_ports', [])),
                    json.dumps(profile.get('vulnerabilities', [])),
                    json.dumps(profile.get('successful_tools', [])),
                    json.dumps(profile.get('failed_tools', [])),
                    1 if profile.get('waf_detected') else 0,
                    now,
                    now
                ))
            
            conn.commit()
            logger.info(f"Stored target profile: {target_hash}")
            
            return target_hash
            
        except Exception as e:
            logger.error(f"Error storing target profile: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def get_target_profile(self, target: str) -> Optional[Dict]:
        """Get stored profile for a target"""
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM target_profiles WHERE target_hash = ?', (target_hash,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'target_hash': row[1],
                    'target_type': row[2],
                    'technologies': json.loads(row[3]) if row[3] else [],
                    'open_ports': json.loads(row[4]) if row[4] else [],
                    'vulnerabilities_found': json.loads(row[5]) if row[5] else [],
                    'successful_tools': json.loads(row[6]) if row[6] else [],
                    'failed_tools': json.loads(row[7]) if row[7] else [],
                    'waf_detected': bool(row[8]),
                    'first_seen': row[9],
                    'last_seen': row[10],
                    'scan_count': row[11]
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting target profile: {e}")
            return None
        finally:
            conn.close()
    
    def find_similar_targets(self, profile: Dict, limit: int = 5) -> List[Dict]:
        """Find targets with similar characteristics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get all profiles
            cursor.execute('SELECT * FROM target_profiles')
            rows = cursor.fetchall()
            
            similarities = []
            target_techs = set(profile.get('technologies', []))
            target_ports = set(profile.get('open_ports', []))
            
            for row in rows:
                stored_techs = set(json.loads(row[3])) if row[3] else set()
                stored_ports = set(json.loads(row[4])) if row[4] else set()
                
                # Calculate similarity score
                tech_similarity = len(target_techs & stored_techs) / max(len(target_techs | stored_techs), 1)
                port_similarity = len(target_ports & stored_ports) / max(len(target_ports | stored_ports), 1)
                
                overall_similarity = (tech_similarity * 0.7) + (port_similarity * 0.3)
                
                if overall_similarity > 0.3:  # Threshold
                    similarities.append({
                        'profile': {
                            'id': row[0],
                            'target_type': row[2],
                            'technologies': list(stored_techs),
                            'open_ports': list(stored_ports),
                            'vulnerabilities_found': json.loads(row[5]) if row[5] else [],
                            'successful_tools': json.loads(row[6]) if row[6] else [],
                            'scan_count': row[11]
                        },
                        'similarity': overall_similarity
                    })
            
            # Sort by similarity
            similarities.sort(key=lambda x: x['similarity'], reverse=True)
            
            return similarities[:limit]
            
        except Exception as e:
            logger.error(f"Error finding similar targets: {e}")
            return []
        finally:
            conn.close()
    
    # ==================== TOOL EFFECTIVENESS ====================
    
    def record_tool_execution(self, tool_name: str, target_type: str, phase: str,
                             context: Dict, success: bool, vulns_found: int,
                             execution_time: float):
        """Record a tool execution for learning"""
        context_hash = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO tool_effectiveness 
                (tool_name, target_type, phase, context_hash, success, vulns_found, 
                 execution_time, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tool_name,
                target_type,
                phase,
                context_hash,
                1 if success else 0,
                vulns_found,
                execution_time,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            
            # Update cache
            cache_key = f"{tool_name}_{target_type}_{phase}"
            if cache_key not in self._tool_stats_cache:
                self._tool_stats_cache[cache_key] = {'success': 0, 'total': 0, 'vulns': 0}
            
            self._tool_stats_cache[cache_key]['total'] += 1
            if success:
                self._tool_stats_cache[cache_key]['success'] += 1
            self._tool_stats_cache[cache_key]['vulns'] += vulns_found
            
        except Exception as e:
            logger.error(f"Error recording tool execution: {e}")
        finally:
            conn.close()
    
    def get_tool_effectiveness(self, tool_name: str, target_type: str = None,
                              phase: str = None) -> Dict[str, float]:
        """Get effectiveness statistics for a tool"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            sql = 'SELECT success, vulns_found, execution_time FROM tool_effectiveness WHERE tool_name = ?'
            params = [tool_name]
            
            if target_type:
                sql += ' AND target_type = ?'
                params.append(target_type)
            
            if phase:
                sql += ' AND phase = ?'
                params.append(phase)
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            
            if not rows:
                return {'success_rate': 0.5, 'avg_vulns': 0, 'avg_time': 0, 'sample_count': 0}
            
            total = len(rows)
            successes = sum(1 for r in rows if r[0])
            total_vulns = sum(r[1] for r in rows)
            avg_time = sum(r[2] for r in rows) / total
            
            return {
                'success_rate': successes / total,
                'avg_vulns': total_vulns / total,
                'avg_time': avg_time,
                'sample_count': total
            }
            
        except Exception as e:
            logger.error(f"Error getting tool effectiveness: {e}")
            return {'success_rate': 0.5, 'avg_vulns': 0, 'avg_time': 0, 'sample_count': 0}
        finally:
            conn.close()
    
    def get_best_tools_for_context(self, target_type: str, phase: str,
                                   limit: int = 5) -> List[Dict]:
        """Get the best performing tools for a given context"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT tool_name, 
                       AVG(success) as success_rate,
                       SUM(vulns_found) as total_vulns,
                       AVG(execution_time) as avg_time,
                       COUNT(*) as sample_count
                FROM tool_effectiveness
                WHERE target_type = ? AND phase = ?
                GROUP BY tool_name
                HAVING sample_count >= 2
                ORDER BY success_rate DESC, total_vulns DESC
                LIMIT ?
            ''', (target_type, phase, limit))
            
            rows = cursor.fetchall()
            
            return [{
                'tool_name': row[0],
                'success_rate': row[1],
                'total_vulns': row[2],
                'avg_time': row[3],
                'sample_count': row[4]
            } for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting best tools: {e}")
            return []
        finally:
            conn.close()
    
    # ==================== VULNERABILITY CHAINS ====================
    
    def store_vuln_chain(self, chain_steps: List[Dict], initial_vuln: str,
                        final_impact: str, success: bool, target_type: str,
                        technology_stack: List[str]) -> str:
        """Store a vulnerability chain (exploit chain)"""
        chain_id = self._generate_id({
            'steps': chain_steps,
            'initial': initial_vuln,
            'final': final_impact
        })
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO vuln_chains 
                (id, chain_steps, initial_vuln, final_impact, success, target_type,
                 technology_stack, discovery_date, use_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 
                        COALESCE((SELECT use_count FROM vuln_chains WHERE id = ?), 0) + 1)
            ''', (
                chain_id,
                json.dumps(chain_steps),
                initial_vuln,
                final_impact,
                1 if success else 0,
                target_type,
                json.dumps(technology_stack),
                datetime.now().isoformat(),
                chain_id
            ))
            
            conn.commit()
            logger.info(f"Stored vulnerability chain: {chain_id}")
            
            # Also store as memory with high importance if successful
            self.store_memory(
                memory_type='vuln_chain',
                content={
                    'chain_steps': chain_steps,
                    'initial_vuln': initial_vuln,
                    'final_impact': final_impact,
                    'success': success,
                    'target_type': target_type
                },
                tags=[target_type, initial_vuln, final_impact],
                importance=0.9 if success else 0.3
            )
            
            return chain_id
            
        except Exception as e:
            logger.error(f"Error storing vulnerability chain: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def get_exploitable_chains(self, initial_vuln: str, target_type: str = None) -> List[Dict]:
        """Get successful chains starting from a given vulnerability"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            sql = 'SELECT * FROM vuln_chains WHERE initial_vuln = ? AND success = 1'
            params = [initial_vuln]
            
            if target_type:
                sql += ' AND target_type = ?'
                params.append(target_type)
            
            sql += ' ORDER BY use_count DESC'
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            
            return [{
                'id': row[0],
                'chain_steps': json.loads(row[1]) if row[1] else [],
                'initial_vuln': row[2],
                'final_impact': row[3],
                'target_type': row[5],
                'technology_stack': json.loads(row[6]) if row[6] else [],
                'use_count': row[8]
            } for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting exploitable chains: {e}")
            return []
        finally:
            conn.close()
    
    # ==================== SCAN HISTORY ====================
    
    def record_scan(self, scan_id: str, target: str, findings: List[Dict],
                   tools_used: List[str], phases_completed: List[str],
                   start_time: str, end_time: str):
        """Record a completed scan for cross-scan learning"""
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
        
        critical_count = len([f for f in findings if f.get('severity', 0) >= 9.0])
        success_score = min(1.0, (len(findings) * 0.1) + (critical_count * 0.3))
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO scan_history 
                (id, target, target_hash, start_time, end_time, findings_count,
                 critical_count, tools_used, phases_completed, success_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                target,
                target_hash,
                start_time,
                end_time,
                len(findings),
                critical_count,
                json.dumps(tools_used),
                json.dumps(phases_completed),
                success_score
            ))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error recording scan: {e}")
        finally:
            conn.close()
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get overall scan statistics for reporting"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT COUNT(*) as total_scans,
                       SUM(findings_count) as total_findings,
                       SUM(critical_count) as total_critical,
                       AVG(success_score) as avg_success
                FROM scan_history
            ''')
            
            row = cursor.fetchone()
            
            return {
                'total_scans': row[0] or 0,
                'total_findings': row[1] or 0,
                'total_critical': row[2] or 0,
                'avg_success_score': row[3] or 0
            }
            
        except Exception as e:
            logger.error(f"Error getting scan statistics: {e}")
            return {}
        finally:
            conn.close()
    
    # ==================== UTILITY METHODS ====================
    
    def _generate_id(self, content: Any) -> str:
        """Generate a unique ID from content"""
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()[:16]
    
    def _content_to_text(self, content: Dict) -> str:
        """Convert content dictionary to searchable text"""
        text_parts = []
        
        def extract_text(obj, prefix=''):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    extract_text(v, f"{prefix}{k} ")
            elif isinstance(obj, list):
                for item in obj:
                    extract_text(item, prefix)
            elif isinstance(obj, (str, int, float)):
                text_parts.append(f"{prefix}{obj}")
        
        extract_text(content)
        return ' '.join(text_parts)
    
    def _generate_embedding(self, text: str) -> Optional[np.ndarray]:
        """Generate a simple embedding for text (can be upgraded to sentence-transformers)"""
        try:
            # Simple bag-of-words embedding with hashing
            words = text.lower().split()
            embedding = np.zeros(self._embedding_dim, dtype=np.float32)
            
            for word in words:
                word_hash = hash(word) % self._embedding_dim
                embedding[word_hash] += 1
            
            # Normalize
            norm = np.linalg.norm(embedding)
            if norm > 0:
                embedding = embedding / norm
            
            return embedding
            
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            return None
    
    def _rank_by_similarity(self, memories: List[MemoryEntry], 
                           query_embedding: np.ndarray) -> List[MemoryEntry]:
        """Rank memories by similarity to query embedding"""
        scored_memories = []
        
        for memory in memories:
            if memory.embedding is not None:
                similarity = np.dot(query_embedding, memory.embedding)
                scored_memories.append((memory, similarity))
            else:
                scored_memories.append((memory, 0))
        
        scored_memories.sort(key=lambda x: x[1], reverse=True)
        return [m for m, s in scored_memories]
    
    def consolidate_memories(self, older_than_days: int = 30):
        """Consolidate old, low-importance memories to save space"""
        cutoff_date = (datetime.now() - timedelta(days=older_than_days)).isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Delete old, low-importance, rarely accessed memories
            cursor.execute('''
                DELETE FROM memories 
                WHERE last_accessed < ? AND importance < 0.5 AND access_count < 3
            ''', (cutoff_date,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            logger.info(f"Consolidated {deleted_count} old memories")
            
            # Vacuum database
            cursor.execute('VACUUM')
            
        except Exception as e:
            logger.error(f"Error consolidating memories: {e}")
        finally:
            conn.close()


# Singleton instance
_memory_system = None

def get_memory_system() -> SmartMemorySystem:
    """Get the singleton memory system instance"""
    global _memory_system
    if _memory_system is None:
        _memory_system = SmartMemorySystem()
    return _memory_system
