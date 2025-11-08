#!/usr/bin/env python3
"""
Advanced Entropy Analysis Scanner
Detects anomalies in files through entropy analysis and statistical methods
"""

import os
import math
import json
import hashlib
import mimetypes
import struct
import numpy as np
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import argparse

class EntropyAnalyzer:
    def __init__(self, chunk_size: int = 256):
        self.chunk_size = chunk_size
        self.results = []
        
        # Entropy thresholds for different file types
        self.thresholds = {
            'text': (2.0, 5.5),      # Plain text files
            'code': (3.0, 6.0),      # Source code
            'binary': (5.0, 7.5),    # Compiled binaries
            'compressed': (7.5, 8.0), # Compressed/encrypted
            'encrypted': (7.8, 8.0),  # Fully encrypted
            'media': (6.0, 7.8),      # Audio/video files
        }
        
        # Known file signatures (magic bytes)
        self.signatures = {
            b'\x50\x4B\x03\x04': 'ZIP/JAR/Office',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x4D\x5A': 'PE/EXE',
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89\x50\x4E\x47': 'PNG',
            b'\x47\x49\x46\x38': 'GIF',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x52\x61\x72\x21': 'RAR',
            b'\x1F\x8B': 'GZIP',
            b'BZh': 'BZIP2',
            b'\xFD\x37\x7A\x58\x5A': 'XZ',
            b'\x4F\x67\x67\x53': 'OGG',
            b'\x52\x49\x46\x46': 'RIFF/WAV/AVI',
            b'\x00\x00\x00\x18\x66\x74\x79\x70': 'MP4',
            b'\x1A\x45\xDF\xA3': 'MKV/WebM',
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0.0
            
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
            
        entropy = 0.0
        data_len = len(data)
        
        for count in freq.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
                
        return entropy

    def calculate_chi_squared(self, data: bytes) -> float:
        """Calculate chi-squared statistic for randomness test"""
        if not data:
            return 0.0
            
        expected = len(data) / 256
        observed = [0] * 256
        
        for byte in data:
            observed[byte] += 1
            
        chi_squared = sum((o - expected) ** 2 / expected for o in observed if expected > 0)
        return chi_squared

    def detect_file_type(self, filepath: Path) -> Dict:
        """Detect file type through multiple methods"""
        result = {
            'extension': filepath.suffix.lower(),
            'mime_type': mimetypes.guess_type(str(filepath))[0],
            'magic_signature': None,
            'detected_type': 'unknown'
        }
        
        try:
            with open(filepath, 'rb') as f:
                header = f.read(32)
                
                # Check magic signatures
                for sig, ftype in self.signatures.items():
                    if header.startswith(sig):
                        result['magic_signature'] = ftype
                        break
                        
                # Detect by entropy patterns
                f.seek(0)
                sample = f.read(8192)
                entropy = self.calculate_entropy(sample)
                
                if entropy < 5.5:
                    result['detected_type'] = 'text/code'
                elif entropy < 7.5:
                    result['detected_type'] = 'binary/media'
                else:
                    result['detected_type'] = 'compressed/encrypted'
                    
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def analyze_entropy_distribution(self, filepath: Path) -> Dict:
        """Analyze entropy distribution across file chunks"""
        chunks_entropy = []
        anomalous_chunks = []
        
        try:
            file_size = filepath.stat().st_size
            with open(filepath, 'rb') as f:
                position = 0
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                        
                    entropy = self.calculate_entropy(chunk)
                    chunks_entropy.append({
                        'position': position,
                        'entropy': entropy,
                        'size': len(chunk)
                    })
                    
                    # Detect anomalous chunks (sudden entropy changes)
                    if len(chunks_entropy) > 1:
                        prev_entropy = chunks_entropy[-2]['entropy']
                        if abs(entropy - prev_entropy) > 2.0:
                            anomalous_chunks.append({
                                'position': position,
                                'entropy_delta': entropy - prev_entropy,
                                'type': 'sudden_change'
                            })
                            
                    position += len(chunk)
                    
            # Statistical analysis
            if chunks_entropy:
                entropies = [c['entropy'] for c in chunks_entropy]
                return {
                    'total_chunks': len(chunks_entropy),
                    'mean_entropy': np.mean(entropies),
                    'std_entropy': np.std(entropies),
                    'min_entropy': min(entropies),
                    'max_entropy': max(entropies),
                    'entropy_variance': np.var(entropies),
                    'anomalous_chunks': anomalous_chunks,
                    'distribution': chunks_entropy[:50] if len(chunks_entropy) > 50 else chunks_entropy
                }
        except Exception as e:
            return {'error': str(e)}
            
        return {}

    def detect_steganography_indicators(self, filepath: Path) -> Dict:
        """Detect potential steganography indicators"""
        indicators = {
            'suspicious': False,
            'reasons': [],
            'confidence': 0.0
        }
        
        try:
            file_type = self.detect_file_type(filepath)
            
            # Check for size anomalies
            file_size = filepath.stat().st_size
            
            # Analyze LSB distribution for images
            if file_type['detected_type'] in ['image', 'media'] or \
               filepath.suffix.lower() in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
                with open(filepath, 'rb') as f:
                    data = f.read(min(file_size, 1048576))  # Read first 1MB
                    
                    # Check LSB distribution
                    lsb_bits = [byte & 1 for byte in data[1000:2000]]  # Sample middle section
                    lsb_ratio = sum(lsb_bits) / len(lsb_bits) if lsb_bits else 0
                    
                    # Perfect 50/50 distribution is suspicious
                    if 0.45 < lsb_ratio < 0.55:
                        indicators['suspicious'] = True
                        indicators['reasons'].append(f'LSB distribution anomaly: {lsb_ratio:.3f}')
                        indicators['confidence'] += 0.3
                        
            # Check entropy at end of file (common hiding spot)
            with open(filepath, 'rb') as f:
                f.seek(max(0, file_size - 1024))
                tail_data = f.read()
                tail_entropy = self.calculate_entropy(tail_data)
                
                if tail_entropy > 7.5:
                    indicators['suspicious'] = True
                    indicators['reasons'].append(f'High entropy at EOF: {tail_entropy:.2f}')
                    indicators['confidence'] += 0.4
                    
            # Check for appended data after expected EOF
            if file_type['magic_signature'] in ['JPEG', 'PNG', 'GIF']:
                with open(filepath, 'rb') as f:
                    content = f.read()
                    
                    # Look for JPEG EOI marker
                    if file_type['magic_signature'] == 'JPEG':
                        eoi_pos = content.find(b'\xFF\xD9')
                        if eoi_pos != -1 and eoi_pos < len(content) - 2:
                            extra_bytes = len(content) - eoi_pos - 2
                            if extra_bytes > 100:
                                indicators['suspicious'] = True
                                indicators['reasons'].append(f'Data after EOI: {extra_bytes} bytes')
                                indicators['confidence'] += 0.5
                                
        except Exception as e:
            indicators['error'] = str(e)
            
        indicators['confidence'] = min(indicators['confidence'], 1.0)
        return indicators

    def detect_packing_obfuscation(self, filepath: Path) -> Dict:
        """Detect packed or obfuscated executables"""
        results = {
            'packed': False,
            'obfuscated': False,
            'indicators': [],
            'packer_signatures': []
        }
        
        try:
            if filepath.suffix.lower() not in ['.exe', '.dll', '.so', '.elf', '']:
                return results
                
            with open(filepath, 'rb') as f:
                data = f.read(min(filepath.stat().st_size, 1048576))
                
                # Check for high entropy in code sections
                entropy = self.calculate_entropy(data[:65536])
                if entropy > 7.0:
                    results['packed'] = True
                    results['indicators'].append(f'High entropy in header: {entropy:.2f}')
                    
                # Common packer signatures
                packer_sigs = {
                    b'UPX!': 'UPX',
                    b'ASPack': 'ASPack',
                    b'PECompact': 'PECompact',
                    b'Themida': 'Themida',
                    b'VMProtect': 'VMProtect',
                    b'.petite': 'Petite',
                    b'NSPack': 'NSPack'
                }
                
                for sig, packer in packer_sigs.items():
                    if sig in data:
                        results['packed'] = True
                        results['packer_signatures'].append(packer)
                        
                # Check for obfuscation patterns
                # Low number of imports (hidden imports)
                if b'KERNEL32.dll' in data:
                    import_count = data.count(b'.dll')
                    if import_count < 3:
                        results['obfuscated'] = True
                        results['indicators'].append(f'Low import count: {import_count}')
                        
                # Check for anti-analysis strings
                anti_analysis = [
                    b'IsDebuggerPresent',
                    b'CheckRemoteDebuggerPresent',
                    b'NtQueryInformationProcess',
                    b'VirtualProtect',
                    b'VirtualAlloc',
                    b'WriteProcessMemory'
                ]
                
                for technique in anti_analysis:
                    if technique in data:
                        results['obfuscated'] = True
                        results['indicators'].append(f'Anti-analysis: {technique.decode("utf-8", errors="ignore")}')
                        
        except Exception as e:
            results['error'] = str(e)
            
        return results

    def analyze_file(self, filepath: Path) -> Dict:
        """Comprehensive file analysis"""
        result = {
            'file': str(filepath),
            'size': filepath.stat().st_size,
            'hash_md5': None,
            'hash_sha256': None,
            'file_type': {},
            'entropy': {},
            'distribution': {},
            'steganography': {},
            'packing': {},
            'anomalies': []
        }
        
        try:
            # Calculate hashes
            with open(filepath, 'rb') as f:
                data = f.read()
                result['hash_md5'] = hashlib.md5(data).hexdigest()
                result['hash_sha256'] = hashlib.sha256(data).hexdigest()
                
            # File type detection
            result['file_type'] = self.detect_file_type(filepath)
            
            # Overall entropy
            with open(filepath, 'rb') as f:
                full_data = f.read()
                result['entropy']['overall'] = self.calculate_entropy(full_data)
                result['entropy']['chi_squared'] = self.calculate_chi_squared(full_data)
                
            # Entropy distribution
            result['distribution'] = self.analyze_entropy_distribution(filepath)
            
            # Steganography detection
            result['steganography'] = self.detect_steganography_indicators(filepath)
            
            # Packing/obfuscation detection
            result['packing'] = self.detect_packing_obfuscation(filepath)
            
            # Identify anomalies
            self._identify_anomalies(result)
            
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def _identify_anomalies(self, result: Dict):
        """Identify and classify anomalies"""
        anomalies = []
        
        # Entropy anomalies
        entropy = result['entropy'].get('overall', 0)
        file_ext = result['file_type'].get('extension', '')
        
        # Check entropy vs expected for file type
        if file_ext in ['.txt', '.log', '.csv', '.json', '.xml', '.html']:
            if entropy > 6.5:
                anomalies.append({
                    'type': 'CRITICAL',
                    'category': 'entropy',
                    'message': f'Text file with encryption-level entropy: {entropy:.2f}',
                    'severity': 9
                })
        elif file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
            if entropy > 7.95:
                anomalies.append({
                    'type': 'WARNING',
                    'category': 'entropy',
                    'message': f'Image file with suspiciously high entropy: {entropy:.2f}',
                    'severity': 7
                })
                
        # File type mismatch
        if result['file_type'].get('magic_signature'):
            expected_ext = result['file_type']['magic_signature'].lower()
            if file_ext and expected_ext not in file_ext and file_ext not in expected_ext.lower():
                anomalies.append({
                    'type': 'WARNING',
                    'category': 'filetype',
                    'message': f'Extension mismatch: {file_ext} but signature shows {expected_ext}',
                    'severity': 6
                })
                
        # Steganography indicators
        if result['steganography'].get('suspicious'):
            anomalies.append({
                'type': 'WARNING',
                'category': 'steganography',
                'message': f'Possible steganography: {", ".join(result["steganography"]["reasons"])}',
                'severity': 8,
                'confidence': result['steganography']['confidence']
            })
            
        # Packing/obfuscation
        if result['packing'].get('packed'):
            anomalies.append({
                'type': 'INFO',
                'category': 'packing',
                'message': f'Packed executable detected: {", ".join(result["packing"]["packer_signatures"])}',
                'severity': 5
            })
            
        if result['packing'].get('obfuscated'):
            anomalies.append({
                'type': 'WARNING',
                'category': 'obfuscation',
                'message': f'Obfuscation detected: {", ".join(result["packing"]["indicators"])}',
                'severity': 7
            })
            
        # Distribution anomalies
        if result['distribution'].get('anomalous_chunks'):
            anomalies.append({
                'type': 'INFO',
                'category': 'distribution',
                'message': f'Entropy distribution anomalies at {len(result["distribution"]["anomalous_chunks"])} locations',
                'severity': 4
            })
            
        result['anomalies'] = sorted(anomalies, key=lambda x: x['severity'], reverse=True)

    def scan_directory(self, directory: Path, recursive: bool = True) -> List[Dict]:
        """Scan entire directory for anomalies"""
        results = []
        
        pattern = '**/*' if recursive else '*'
        files = [f for f in directory.glob(pattern) if f.is_file()]
        
        print(f"\n[*] Scanning {len(files)} files in {directory}")
        print("-" * 60)
        
        for i, filepath in enumerate(files, 1):
            print(f"[{i}/{len(files)}] Analyzing: {filepath.name}")
            
            try:
                analysis = self.analyze_file(filepath)
                results.append(analysis)
                
                # Print immediate warnings
                if analysis['anomalies']:
                    for anomaly in analysis['anomalies']:
                        if anomaly['severity'] >= 7:
                            print(f"    ⚠️  {anomaly['message']}")
                            
            except Exception as e:
                print(f"    ❌ Error: {e}")
                
        return results

    def generate_report(self, results: List[Dict], output_file: Optional[str] = None):
        """Generate comprehensive report"""
        report = {
            'scan_timestamp': str(Path.ctime(Path.cwd())),
            'total_files': len(results),
            'anomalous_files': [],
            'statistics': {
                'high_entropy_files': [],
                'suspected_steganography': [],
                'packed_executables': [],
                'type_mismatches': [],
                'critical_anomalies': []
            },
            'detailed_results': results
        }
        
        for result in results:
            if result.get('anomalies'):
                report['anomalous_files'].append({
                    'file': result['file'],
                    'anomalies': result['anomalies'],
                    'entropy': result['entropy'].get('overall', 0)
                })
                
            # Categorize findings
            if result['entropy'].get('overall', 0) > 7.8:
                report['statistics']['high_entropy_files'].append(result['file'])
                
            if result['steganography'].get('suspicious'):
                report['statistics']['suspected_steganography'].append(result['file'])
                
            if result['packing'].get('packed'):
                report['statistics']['packed_executables'].append(result['file'])
                
            for anomaly in result.get('anomalies', []):
                if anomaly['severity'] >= 9:
                    report['statistics']['critical_anomalies'].append({
                        'file': result['file'],
                        'anomaly': anomaly
                    })
                    
        # Print summary
        print("\n" + "=" * 60)
        print("ENTROPY ANALYSIS REPORT")
        print("=" * 60)
        print(f"Total files analyzed: {report['total_files']}")
        print(f"Anomalous files: {len(report['anomalous_files'])}")
        print(f"High entropy files: {len(report['statistics']['high_entropy_files'])}")
        print(f"Suspected steganography: {len(report['statistics']['suspected_steganography'])}")
        print(f"Packed executables: {len(report['statistics']['packed_executables'])}")
        print(f"Critical anomalies: {len(report['statistics']['critical_anomalies'])}")
        
        if report['statistics']['critical_anomalies']:
            print("\n⚠️  CRITICAL FINDINGS:")
            for finding in report['statistics']['critical_anomalies']:
                print(f"  - {finding['file']}: {finding['anomaly']['message']}")
                
        # Save report if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Detailed report saved to: {output_file}")
            
        return report

def main():
    parser = argparse.ArgumentParser(description='Advanced Entropy Analysis Scanner')
    parser.add_argument('path', help='Path to file or directory to analyze')
    parser.add_argument('-r', '--recursive', action='store_true', help='Scan recursively')
    parser.add_argument('-c', '--chunk-size', type=int, default=256, help='Chunk size for analysis')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('--threshold', type=float, default=7.5, help='Entropy threshold for warnings')
    
    args = parser.parse_args()
    
    analyzer = EntropyAnalyzer(chunk_size=args.chunk_size)
    path = Path(args.path)
    
    if path.is_file():
        result = analyzer.analyze_file(path)
        print(json.dumps(result, indent=2))
    elif path.is_dir():
        results = analyzer.scan_directory(path, recursive=args.recursive)
        analyzer.generate_report(results, args.output)
    else:
        print(f"Error: {path} not found")
        return 1
        
    return 0

if __name__ == "__main__":
    exit(main())
