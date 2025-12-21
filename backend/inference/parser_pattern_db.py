"""
Self-Learning Pattern Database for Parser
Stores successful parsing patterns for reuse, reducing LLM calls over time
"""

import json
import hashlib
import sqlite3
import re
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class ParsePattern:
    """Represents a learned parsing pattern"""
    tool: str
    output_signature: str
    structural_features: Dict[str, Any]
    extraction_patterns: List[str]  # Regex patterns that worked
    field_mappings: Dict[str, str]  # How to map extracted data to fields
    success_count: int = 1
    failure_count: int = 0
    last_used: str = ""
    confidence_boost: float = 0.0
    created_at: str = ""
    
    def effectiveness_score(self) -> float:
        """Calculate pattern effectiveness"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total


class ParserPatternDB:
    """
    SQLite-backed pattern database for learned parsing patterns.
    
    Key features:
    - Stores structural signatures of outputs for matching
    - Learns regex patterns that successfully extracted data
    - Tracks pattern effectiveness over time
    - Auto-cleanup of ineffective patterns
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent / 'data' / 'parser_patterns.db'
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        logger.info(f"[ParserPatternDB] Initialized at {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT NOT NULL,
                    output_signature TEXT NOT NULL,
                    structural_features TEXT,
                    extraction_patterns TEXT,
                    field_mappings TEXT,
                    success_count INTEGER DEFAULT 1,
                    failure_count INTEGER DEFAULT 0,
                    last_used TEXT,
                    confidence_boost REAL DEFAULT 0.0,
                    created_at TEXT,
                    UNIQUE(tool, output_signature)
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_tool_sig 
                ON patterns(tool, output_signature)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_tool_success
                ON patterns(tool, success_count DESC)
            ''')
            
            # Cleanup table for tracking deletions
            conn.execute('''
                CREATE TABLE IF NOT EXISTS pattern_stats (
                    id INTEGER PRIMARY KEY,
                    total_patterns INTEGER DEFAULT 0,
                    total_lookups INTEGER DEFAULT 0,
                    total_hits INTEGER DEFAULT 0,
                    last_cleanup TEXT
                )
            ''')
            
            # Initialize stats row if not exists
            conn.execute('''
                INSERT OR IGNORE INTO pattern_stats (id, total_patterns, total_lookups, total_hits)
                VALUES (1, 0, 0, 0)
            ''')
    
    def compute_signature(self, output: str) -> str:
        """
        Compute structural signature of output.
        
        This captures the OUTPUT STRUCTURE, not content, so similar
        outputs from the same tool will match.
        """
        features = []
        
        # Basic metrics
        lines = output.split('\n')
        features.append(f"lines:{len(lines)//10*10}")  # Round to nearest 10
        features.append(f"chars:{len(output)//100*100}")  # Round to nearest 100
        
        # Format detection
        features.append(f"json:{'1' if self._looks_like_json(output) else '0'}")
        features.append(f"xml:{'1' if self._looks_like_xml(output) else '0'}")
        features.append(f"table:{'1' if self._looks_like_table(output) else '0'}")
        
        # Line structure patterns (first 20 non-empty lines)
        line_patterns = []
        for line in lines[:30]:
            line = line.strip()
            if not line:
                continue
            if len(line_patterns) >= 20:
                break
            
            # Capture line start pattern
            if line[0:1].isalpha():
                line_patterns.append('A')
            elif line[0:1].isdigit():
                line_patterns.append('D')
            elif line[0:1] in '[{(':
                line_patterns.append('B')  # Bracket
            elif line[0:1] in '+-*#':
                line_patterns.append('M')  # Marker
            elif line[0:1] in '|':
                line_patterns.append('P')  # Pipe (table)
            else:
                line_patterns.append('S')  # Special
        
        features.append(f"lp:{''.join(line_patterns[:20])}")
        
        # Common delimiters
        features.append(f"tabs:{output.count(chr(9))//10}")
        features.append(f"pipes:{output.count('|')//10}")
        features.append(f"colons:{output.count(':')//50}")
        
        # Security-specific markers
        vuln_markers = ['vulnerability', 'vuln', 'cve', 'critical', 'high', 'medium', 'low', 'finding']
        marker_count = sum(1 for m in vuln_markers if m in output.lower())
        features.append(f"vuln_markers:{marker_count}")
        
        # Create hash
        signature_str = '|'.join(features)
        return hashlib.md5(signature_str.encode()).hexdigest()[:16]
    
    def _looks_like_json(self, output: str) -> bool:
        """Check if output looks like JSON"""
        stripped = output.strip()
        return (stripped.startswith('{') and stripped.endswith('}')) or \
               (stripped.startswith('[') and stripped.endswith(']'))
    
    def _looks_like_xml(self, output: str) -> bool:
        """Check if output looks like XML"""
        stripped = output.strip()
        return stripped.startswith('<?xml') or \
               (stripped.startswith('<') and stripped.endswith('>') and '</' in stripped)
    
    def _looks_like_table(self, output: str) -> bool:
        """Check if output looks like a table"""
        lines = output.split('\n')[:20]
        pipe_lines = sum(1 for l in lines if '|' in l)
        tab_lines = sum(1 for l in lines if '\t' in l)
        return pipe_lines >= 3 or tab_lines >= 3
    
    def extract_structural_features(self, output: str) -> Dict[str, Any]:
        """Extract detailed structural features for pattern matching"""
        lines = output.split('\n')
        
        return {
            'line_count': len(lines),
            'char_count': len(output),
            'has_json': self._looks_like_json(output),
            'has_xml': self._looks_like_xml(output),
            'has_table': self._looks_like_table(output),
            'empty_line_ratio': sum(1 for l in lines if not l.strip()) / max(len(lines), 1),
            'avg_line_length': sum(len(l) for l in lines) / max(len(lines), 1),
            'unique_first_chars': len(set(l[0:1] for l in lines if l.strip())),
        }
    
    def find_pattern(self, tool: str, output: str) -> Optional[ParsePattern]:
        """
        Find matching pattern for output.
        
        Args:
            tool: Tool name
            output: Raw output to match
            
        Returns:
            Matching ParsePattern or None
        """
        signature = self.compute_signature(output)
        
        with self._get_connection() as conn:
            # Update lookup stats
            conn.execute('UPDATE pattern_stats SET total_lookups = total_lookups + 1 WHERE id = 1')
            
            cursor = conn.execute(
                '''SELECT * FROM patterns 
                   WHERE tool = ? AND output_signature = ?
                   AND success_count >= 2
                   AND (success_count * 1.0 / (success_count + failure_count + 1)) >= 0.5
                ''',
                (tool, signature)
            )
            row = cursor.fetchone()
            
            if row:
                # Update stats
                conn.execute('UPDATE pattern_stats SET total_hits = total_hits + 1 WHERE id = 1')
                conn.execute(
                    'UPDATE patterns SET last_used = ? WHERE id = ?',
                    (datetime.now().isoformat(), row['id'])
                )
                
                return ParsePattern(
                    tool=row['tool'],
                    output_signature=row['output_signature'],
                    structural_features=json.loads(row['structural_features'] or '{}'),
                    extraction_patterns=json.loads(row['extraction_patterns'] or '[]'),
                    field_mappings=json.loads(row['field_mappings'] or '{}'),
                    success_count=row['success_count'],
                    failure_count=row['failure_count'],
                    last_used=row['last_used'] or '',
                    confidence_boost=row['confidence_boost'],
                    created_at=row['created_at'] or ''
                )
        
        return None
    
    def store_pattern(self, tool: str, output: str, 
                      extraction_patterns: List[str],
                      field_mappings: Dict[str, str],
                      human_verified: bool = False) -> bool:
        """
        Store a successful parsing pattern.
        
        Args:
            tool: Tool name
            output: Raw output that was successfully parsed
            extraction_patterns: Regex patterns that worked
            field_mappings: Field name mappings
            human_verified: Whether a human verified this parsing
            
        Returns:
            True if stored successfully
        """
        signature = self.compute_signature(output)
        features = self.extract_structural_features(output)
        confidence = 0.15 if human_verified else 0.05
        now = datetime.now().isoformat()
        
        try:
            with self._get_connection() as conn:
                # Try to insert new pattern
                try:
                    conn.execute('''
                        INSERT INTO patterns 
                        (tool, output_signature, structural_features, extraction_patterns, 
                         field_mappings, confidence_boost, created_at, last_used, success_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                    ''', (
                        tool, signature,
                        json.dumps(features),
                        json.dumps(extraction_patterns),
                        json.dumps(field_mappings),
                        confidence,
                        now, now
                    ))
                    
                    # Update stats
                    conn.execute('UPDATE pattern_stats SET total_patterns = total_patterns + 1 WHERE id = 1')
                    logger.debug(f"[ParserPatternDB] Stored new pattern for {tool}")
                    
                except sqlite3.IntegrityError:
                    # Pattern exists, update it
                    conn.execute('''
                        UPDATE patterns 
                        SET confidence_boost = MIN(confidence_boost + ?, 0.3),
                            success_count = success_count + 1,
                            last_used = ?,
                            extraction_patterns = ?,
                            field_mappings = ?
                        WHERE tool = ? AND output_signature = ?
                    ''', (
                        confidence, now,
                        json.dumps(extraction_patterns),
                        json.dumps(field_mappings),
                        tool, signature
                    ))
                    logger.debug(f"[ParserPatternDB] Updated existing pattern for {tool}")
                
            return True
            
        except Exception as e:
            logger.error(f"[ParserPatternDB] Failed to store pattern: {e}")
            return False
    
    def record_failure(self, tool: str, output: str):
        """Record a pattern matching failure"""
        signature = self.compute_signature(output)
        
        try:
            with self._get_connection() as conn:
                conn.execute('''
                    UPDATE patterns 
                    SET failure_count = failure_count + 1
                    WHERE tool = ? AND output_signature = ?
                ''', (tool, signature))
        except Exception as e:
            logger.warning(f"[ParserPatternDB] Failed to record failure: {e}")
    
    def get_tool_patterns(self, tool: str, limit: int = 10) -> List[ParsePattern]:
        """Get top patterns for a tool"""
        patterns = []
        
        with self._get_connection() as conn:
            cursor = conn.execute(
                '''SELECT * FROM patterns WHERE tool = ? 
                   ORDER BY success_count DESC, confidence_boost DESC
                   LIMIT ?''',
                (tool, limit)
            )
            
            for row in cursor:
                patterns.append(ParsePattern(
                    tool=row['tool'],
                    output_signature=row['output_signature'],
                    structural_features=json.loads(row['structural_features'] or '{}'),
                    extraction_patterns=json.loads(row['extraction_patterns'] or '[]'),
                    field_mappings=json.loads(row['field_mappings'] or '{}'),
                    success_count=row['success_count'],
                    failure_count=row['failure_count'],
                    last_used=row['last_used'] or '',
                    confidence_boost=row['confidence_boost'],
                    created_at=row['created_at'] or ''
                ))
        
        return patterns
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self._get_connection() as conn:
            stats_row = conn.execute('SELECT * FROM pattern_stats WHERE id = 1').fetchone()
            
            tool_counts = conn.execute(
                'SELECT tool, COUNT(*) as count FROM patterns GROUP BY tool'
            ).fetchall()
            
            return {
                'total_patterns': stats_row['total_patterns'] if stats_row else 0,
                'total_lookups': stats_row['total_lookups'] if stats_row else 0,
                'total_hits': stats_row['total_hits'] if stats_row else 0,
                'hit_rate': (stats_row['total_hits'] / max(stats_row['total_lookups'], 1)) if stats_row else 0,
                'patterns_by_tool': {row['tool']: row['count'] for row in tool_counts}
            }
    
    def cleanup_ineffective_patterns(self, min_attempts: int = 10, 
                                     min_success_rate: float = 0.3):
        """Remove patterns that have proven ineffective"""
        try:
            with self._get_connection() as conn:
                result = conn.execute('''
                    DELETE FROM patterns 
                    WHERE (success_count + failure_count) >= ?
                    AND (success_count * 1.0 / (success_count + failure_count)) < ?
                ''', (min_attempts, min_success_rate))
                
                deleted = result.rowcount
                if deleted > 0:
                    logger.info(f"[ParserPatternDB] Cleaned up {deleted} ineffective patterns")
                    conn.execute(
                        'UPDATE pattern_stats SET last_cleanup = ? WHERE id = 1',
                        (datetime.now().isoformat(),)
                    )
                
                return deleted
                
        except Exception as e:
            logger.error(f"[ParserPatternDB] Cleanup failed: {e}")
            return 0


# Singleton
_pattern_db = None


def get_pattern_db() -> ParserPatternDB:
    """Get or create singleton pattern database"""
    global _pattern_db
    if _pattern_db is None:
        _pattern_db = ParserPatternDB()
    return _pattern_db
