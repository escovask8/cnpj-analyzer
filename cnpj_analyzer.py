#!/usr/bin/env python3
"""
CNPJ Analyzer - A tool to scan source code files for CNPJ usage patterns.

This script recursively traverses a target folder, analyzes all source code files,
and identifies all occurrences of the term "CNPJ" (case-insensitive) and its synonyms.
For each occurrence, the tool interprets how the CNPJ is being used and classifies it
with a confidence level, focusing on Java/Spring patterns.
"""

import os
import re
import csv
import time
import logging
import argparse
import chardet
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor
import fnmatch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('cnpj_analyzer')

@dataclass
class CNPJOccurrence:
    """Class to store information about a CNPJ occurrence in code."""
    file_path: str
    relative_path: str
    line_number: int
    code_snippet: str
    classification: str
    inferred_type: str
    details: str
    cnpj_role: str
    confidence_score: float

class CNPJAnalyzer:
    """Main class for analyzing CNPJ usage in source code files."""
    
    # Default configuration
    DEFAULT_EXCLUDE_DIRS = ['.git', 'node_modules', 'build', 'dist', 'venv', '__pycache__', '.idea', '.vscode', 'target', 'bin']
    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Regex patterns for CNPJ detection
    CNPJ_PATTERN = r'\b(cnpj|cadastro nacional da pessoa jurídica|company tax id|14[- ]?digit (company )?id|brazilian company tax id)\b'
    
    # Java-specific patterns
    JAVA_STRING_DECLARATION = r'(?:String|CharSequence|StringBuilder|StringBuffer)\s+\w*cnpj\w*\s*='
    JAVA_NUMERIC_DECLARATION = r'(?:long|Long|int|Integer|BigInteger|double|Double|BigDecimal)\s+\w*cnpj\w*\s*='
    JAVA_ANNOTATION_PATTERN = r'@(?:Column|Size|Pattern|NotNull|Valid|JsonProperty)(?:\(.*?(?:cnpj|CNPJ).*?\))?'
    JAVA_METHOD_PATTERN = r'(?:public|private|protected)?\s+\w+\s+\w*(?:validate|check|format|parse|get|set|is|has)(?:Cnpj|CNPJ)\w*\s*\('
    
    # Spring-specific patterns
    SPRING_CONTROLLER_PATTERN = r'@(?:RestController|Controller|RequestMapping)'
    SPRING_ENTITY_PATTERN = r'@Entity'
    SPRING_REPOSITORY_PATTERN = r'@Repository'
    SPRING_SERVICE_PATTERN = r'@Service'
    
    # Classification patterns
    STRING_LITERAL_PATTERN = r'(?:\'|").*?(?:cnpj|CNPJ).*?(?:\'|")'
    NUMERIC_LITERAL_PATTERN = r'\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}\-?\d{2}\b'
    JAVA_CONVERSION_PATTERNS = [
        r'Long\.parseLong\(\s*\w*cnpj\w*\.replaceAll\(\s*"\\D"\s*,\s*""\s*\)\s*\)',
        r'Integer\.parseInt\(\s*\w*cnpj\w*\.replaceAll\(\s*"\\D"\s*,\s*""\s*\)\s*\)',
        r'new\s+BigInteger\(\s*\w*cnpj\w*\.replaceAll\(\s*"\\D"\s*,\s*""\s*\)\s*\)',
        r'Long\.valueOf\(\s*\w*cnpj\w*\.replaceAll\(\s*"\\D"\s*,\s*""\s*\)\s*\)'
    ]
    JAVA_SANITIZATION_PATTERNS = [
        r'\w*cnpj\w*\.replaceAll\(\s*"\\D"\s*,\s*""\s*\)',
        r'\w*cnpj\w*\.replace\(\s*"\."\s*,\s*""\s*\)\.replace\(\s*"/"\s*,\s*""\s*\)\.replace\(\s*"-"\s*,\s*""\s*\)',
        r'StringUtils\.removeNonDigits\(\s*\w*cnpj\w*\s*\)'
    ]
    JAVA_VALIDATION_PATTERNS = [
        r'(?:validate|valid|check|verify|is)(?:CNPJ|Cnpj|cnpj)',
        r'\w*cnpj\w*\.matches\(\s*"\\d{2}\\.\\d{3}\\.\\d{3}/\\d{4}-\\d{2}"\s*\)',
        r'\w*cnpj\w*\.length\(\)\s*(?:==|===)\s*14',
        r'@Pattern\(regexp\s*=\s*"\\d{2}\\.\\d{3}\\.\\d{3}/\\d{4}-\\d{2}"\s*\)'
    ]
    JAVA_FORMATTING_PATTERNS = [
        r'String\.format\(\s*"%s\.%s\.%s/%s-%s"\s*,',
        r'new\s+DecimalFormat\(\s*"##\.###\.###/####-##"\s*\)',
        r'MaskFormatter\(\s*"##\.###\.###/####-##"\s*\)'
    ]
    JAVA_DB_FIELD_PATTERNS = [
        r'@Column\(\s*name\s*=\s*"(?:cnpj|CNPJ)"\s*,\s*length\s*=\s*\d+\s*\)',
        r'@Column\(\s*name\s*=\s*"(?:cnpj|CNPJ)"\s*\)',
        r'CREATE\s+TABLE.*?(?:cnpj|CNPJ).*?VARCHAR',
        r'CREATE\s+TABLE.*?(?:cnpj|CNPJ).*?CHAR',
        r'CREATE\s+TABLE.*?(?:cnpj|CNPJ).*?NUMERIC',
        r'INSERT\s+INTO.*?(?:cnpj|CNPJ)',
        r'SELECT.*?FROM.*?WHERE.*?(?:cnpj|CNPJ)'
    ]
    
    def __init__(
        self,
        target_folder: str,
        output_file: str = 'cnpj_analysis.csv',
        exclude_dirs: Optional[List[str]] = None,
        mask_values: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_workers: int = os.cpu_count() or 4,
        java_focus: bool = True,
        include_synonyms: bool = True
    ):
        """Initialize the CNPJ analyzer with configuration options."""
        self.target_folder = os.path.abspath(target_folder)
        self.output_file = output_file
        self.exclude_dirs = exclude_dirs or self.DEFAULT_EXCLUDE_DIRS
        self.mask_values = mask_values
        self.max_file_size = max_file_size
        self.max_workers = max_workers
        self.java_focus = java_focus
        self.include_synonyms = include_synonyms
        
        # Statistics
        self.stats = {
            'total_files_scanned': 0,
            'files_with_cnpj': 0,
            'total_occurrences': 0,
            'ignored_files': 0,
            'execution_time': 0,
            'roles': {}
        }
        
        # Compile regex patterns
        self.cnpj_regex = re.compile(self.CNPJ_PATTERN, re.IGNORECASE) if include_synonyms else re.compile(r'\bcnpj\b', re.IGNORECASE)
        
    def should_process_file(self, file_path: str) -> bool:
        """Check if a file should be processed based on size and binary check."""
        # Check file size
        try:
            if os.path.getsize(file_path) > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path}")
                self.stats['ignored_files'] += 1
                return False
                
            # Try to read the first few bytes to check if it's a text file
            with open(file_path, 'rb') as f:
                sample = f.read(1024)
                if b'\0' in sample:  # Binary file check
                    logger.debug(f"Skipping binary file: {file_path}")
                    self.stats['ignored_files'] += 1
                    return False
            
            # Always process Java files and properties files
            _, ext = os.path.splitext(file_path)
            if ext.lower() in ['.java', '.properties', '.yml', '.yaml', '.xml', '.jsp', '.sql']:
                return True
                    
            return True
        except OSError:
            logger.warning(f"Could not access file: {file_path}")
            self.stats['ignored_files'] += 1
            return False
    
    def should_process_dir(self, dir_path: str) -> bool:
        """Check if a directory should be processed."""
        dir_name = os.path.basename(dir_path)
        return not any(fnmatch.fnmatch(dir_name, pattern) for pattern in self.exclude_dirs)
    
    def get_file_encoding(self, file_path: str) -> str:
        """Detect file encoding."""
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read(4096)
                result = chardet.detect(raw_data)
                return result['encoding'] or 'utf-8'
        except Exception:
            return 'utf-8'  # Default to UTF-8
    
    def is_java_file(self, file_path: str) -> bool:
        """Check if the file is a Java-related file."""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in ['.java', '.properties', '.yml', '.yaml', '.xml', '.jsp', '.sql']
    
    def scan_file(self, file_path: str, relative_path: str) -> List[CNPJOccurrence]:
        """Scan a single file for CNPJ occurrences."""
        occurrences = []
        
        try:
            encoding = self.get_file_encoding(file_path)
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines):
                if self.cnpj_regex.search(line):
                    # Get context (window of lines)
                    start_idx = max(0, i - 5)
                    end_idx = min(len(lines), i + 6)
                    context_lines = lines[start_idx:end_idx]
                    context = ''.join(context_lines)
                    
                    # Classify the occurrence
                    classification, inferred_type, details, role, confidence = self.classify_occurrence(
                        line, context, file_path, i, lines
                    )
                    
                    # Mask CNPJ values if required
                    code_snippet = self.mask_cnpj(context) if self.mask_values else context
                    
                    occurrence = CNPJOccurrence(
                        file_path=file_path,
                        relative_path=relative_path,
                        line_number=i + 1,  # 1-based line numbering
                        code_snippet=code_snippet.strip(),
                        classification=classification,
                        inferred_type=inferred_type,
                        details=details,
                        cnpj_role=role,
                        confidence_score=confidence
                    )
                    occurrences.append(occurrence)
                    
                    # Update role statistics
                    if role in self.stats['roles']:
                        self.stats['roles'][role] += 1
                    else:
                        self.stats['roles'][role] = 1
                    
            if occurrences:
                self.stats['files_with_cnpj'] += 1
                self.stats['total_occurrences'] += len(occurrences)
                
            return occurrences
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            self.stats['ignored_files'] += 1
            return []
    
    def mask_cnpj(self, text: str) -> str:
        """Mask CNPJ values in the text to protect sensitive information."""
        # Simple pattern to find CNPJ-like sequences
        cnpj_pattern = r'\b\d{2}[\.\-]?\d{3}[\.\-]?\d{3}[\/\-]?\d{4}[\-]?\d{2}\b'
        
        def mask_match(match):
            return "[MASKED_CNPJ]"
            
        return re.sub(cnpj_pattern, mask_match, text)
    
    def detect_file_context(self, file_path: str) -> str:
        """Detect the context of the file (controller, entity, service, etc.)."""
        if not self.java_focus or not self.is_java_file(file_path):
            return "unknown"
            
        try:
            with open(file_path, 'r', encoding=self.get_file_encoding(file_path), errors='replace') as f:
                content = f.read()
                
            if re.search(self.SPRING_CONTROLLER_PATTERN, content, re.IGNORECASE):
                return "controller"
            elif re.search(self.SPRING_ENTITY_PATTERN, content, re.IGNORECASE):
                return "entity"
            elif re.search(self.SPRING_REPOSITORY_PATTERN, content, re.IGNORECASE):
                return "repository"
            elif re.search(self.SPRING_SERVICE_PATTERN, content, re.IGNORECASE):
                return "service"
            elif file_path.endswith('.sql'):
                return "sql"
            elif file_path.endswith('.properties') or file_path.endswith('.yml') or file_path.endswith('.yaml'):
                return "configuration"
            else:
                return "java_class"
        except Exception:
            return "unknown"
    
    def classify_occurrence(
        self, line: str, context: str, file_path: str, line_idx: int, all_lines: List[str]
    ) -> Tuple[str, str, str, str, float]:
        """
        Classify a CNPJ occurrence based on its usage pattern.
        
        Returns:
            Tuple of (classification, inferred_type, details, cnpj_role, confidence_score)
        """
        # Default values
        classification = "ambiguous"
        inferred_type = "unknown"
        details = ""
        role = "unknown"
        confidence = 0.3  # Default confidence
        
        # Detect file context for role inference
        file_context = self.detect_file_context(file_path)
        
        # Java-specific analysis if enabled
        if self.java_focus and self.is_java_file(file_path):
            # Check for string declaration
            if re.search(self.JAVA_STRING_DECLARATION, context, re.IGNORECASE):
                classification = "string_declaration"
                inferred_type = "string"
                details = "CNPJ declared as String"
                confidence = 0.9
                
                # Check if it has mask
                if re.search(r'(?:\'|").*?[\./-].*?(?:\'|")', context):
                    inferred_type = "string_with_mask"
                    details += " with formatting (dots/dashes)"
            
            # Check for numeric declaration
            elif re.search(self.JAVA_NUMERIC_DECLARATION, context, re.IGNORECASE):
                classification = "numeric_declaration"
                inferred_type = "numeric"
                details = "CNPJ declared as numeric type"
                confidence = 0.9
            
            # Check for conversion to numeric
            for pattern in self.JAVA_CONVERSION_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    classification = "converted_to_numeric"
                    inferred_type = "string_to_numeric"
                    details = "CNPJ is converted to numeric after sanitization"
                    confidence = 0.95
                    break
            
            # Check for string sanitization
            for pattern in self.JAVA_SANITIZATION_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    if classification != "converted_to_numeric":  # Don't override conversion
                        classification = "string_with_sanitization"
                        inferred_type = "string_sanitized"
                        details = "CNPJ is sanitized (non-digits removed)"
                    confidence = max(confidence, 0.85)
                    break
            
            # Check for validation
            for pattern in self.JAVA_VALIDATION_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    classification = "validated"
                    details += "; Validated using pattern or length check"
                    confidence = max(confidence, 0.9)
                    break
            
            # Check for formatting
            for pattern in self.JAVA_FORMATTING_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    classification = "formatted"
                    inferred_type = "string_with_mask"
                    details += "; Formatted with mask"
                    confidence = max(confidence, 0.85)
                    break
            
            # Check for database field
            for pattern in self.JAVA_DB_FIELD_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    if "VARCHAR" in pattern or "CHAR" in pattern:
                        classification = "db_field_string"
                        inferred_type = "string"
                        details += "; Stored as string in database"
                    else:
                        classification = "db_field_numeric"
                        inferred_type = "numeric"
                        details += "; Stored as numeric in database"
                    confidence = max(confidence, 0.85)
                    break
            
            # Determine role based on context and file type
            if file_context == "controller":
                if re.search(r'@RequestParam', context, re.IGNORECASE) or re.search(r'@PathVariable', context, re.IGNORECASE):
                    role = "API input parameter"
                elif re.search(r'ResponseEntity', context, re.IGNORECASE) or re.search(r'return', context, re.IGNORECASE):
                    role = "API response data"
                else:
                    role = "Controller processing"
            elif file_context == "entity":
                role = "Database entity field"
            elif file_context == "repository":
                role = "Database query parameter"
            elif file_context == "service":
                if re.search(r'validate|check|verify', context, re.IGNORECASE):
                    role = "Business validation"
                else:
                    role = "Business logic processing"
            elif file_context == "sql":
                if re.search(r'CREATE|ALTER', context, re.IGNORECASE):
                    role = "Database schema definition"
                elif re.search(r'INSERT|UPDATE', context, re.IGNORECASE):
                    role = "Database write operation"
                elif re.search(r'SELECT', context, re.IGNORECASE):
                    role = "Database read operation"
            elif file_context == "configuration":
                role = "Configuration property"
            
            # If we still don't have a role, try to infer from method name
            if role == "unknown":
                method_match = re.search(r'(?:public|private|protected)?\s+\w+\s+(\w+)\s*\(', context)
                if method_match:
                    method_name = method_match.group(1).lower()
                    if 'validate' in method_name or 'check' in method_name:
                        role = "Validation method"
                    elif 'format' in method_name or 'mask' in method_name:
                        role = "Formatting method"
                    elif 'parse' in method_name or 'convert' in method_name:
                        role = "Conversion method"
                    elif 'get' in method_name:
                        role = "Getter method"
                    elif 'set' in method_name:
                        role = "Setter method"
        else:
            # Generic analysis for non-Java files
            # Check for string literal
            if re.search(self.STRING_LITERAL_PATTERN, line, re.IGNORECASE):
                classification = "string_literal"
                inferred_type = "string"
                details = "CNPJ appears as a string literal"
                confidence = 0.7
                
                # Check if it has mask
                if re.search(r'(?:\'|").*?[\./-].*?(?:\'|")', line):
                    inferred_type = "string_with_mask"
                    details += " with formatting (dots/dashes)"
            
            # Check for numeric literal
            elif re.search(self.NUMERIC_LITERAL_PATTERN, line):
                classification = "numeric_literal"
                inferred_type = "numeric"
                details = "CNPJ appears as a numeric pattern"
                confidence = 0.6
                
            # Role is harder to determine without language-specific context
            role = "General usage"
        
        # Clean up details (remove leading semicolon if present)
        if details.startswith("; "):
            details = details[2:]
            
        return classification, inferred_type, details, role, confidence
    
    def process_file(self, file_info: Tuple[str, str]) -> List[CNPJOccurrence]:
        """Process a single file (for parallel execution)."""
        file_path, relative_path = file_info
        logger.debug(f"Processing file: {file_path}")
        if self.should_process_file(file_path):
            self.stats['total_files_scanned'] += 1
            occurrences = self.scan_file(file_path, relative_path)
            if occurrences:
                logger.debug(f"Found {len(occurrences)} CNPJ occurrences in {file_path}")
            return occurrences
        return []
    
    def find_files(self) -> List[Tuple[str, str]]:
        """Find all files to be processed."""
        files_to_process = []
        
        for root, dirs, files in os.walk(self.target_folder):
            # Filter directories
            dirs[:] = [d for d in dirs if self.should_process_dir(os.path.join(root, d))]
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, self.target_folder)
                files_to_process.append((file_path, relative_path))
        
        return files_to_process
    
    def export_to_csv(self, occurrences: List[CNPJOccurrence]) -> None:
        """Export the analysis results to a CSV file."""
        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'file_path', 'relative_path', 'line_number', 'code_snippet',
                'classification', 'inferred_type', 'details', 'cnpj_role', 'confidence_score'
            ])
            
            # Write data
            for occurrence in occurrences:
                writer.writerow([
                    occurrence.file_path,
                    occurrence.relative_path,
                    occurrence.line_number,
                    occurrence.code_snippet,
                    occurrence.classification,
                    occurrence.inferred_type,
                    occurrence.details,
                    occurrence.cnpj_role,
                    occurrence.confidence_score
                ])
    
    def run(self) -> None:
        """Run the CNPJ analyzer."""
        start_time = time.time()
        logger.info(f"Starting CNPJ analysis on {self.target_folder}")
        logger.info(f"Java focus: {self.java_focus}")
        logger.info(f"Include synonyms: {self.include_synonyms}")
        
        # Find files to process
        files_to_process = self.find_files()
        logger.info(f"Found {len(files_to_process)} files to scan")
        
        # For small number of files or debugging, use sequential processing
        all_occurrences = []
        if len(files_to_process) < 10 or logger.level == logging.DEBUG:
            for file_info in files_to_process:
                occurrences = self.process_file(file_info)
                all_occurrences.extend(occurrences)
        else:
            # Process files in parallel for larger projects
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                for occurrences in executor.map(self.process_file, files_to_process):
                    all_occurrences.extend(occurrences)
        
        # Export results
        self.export_to_csv(all_occurrences)
        
        # Calculate execution time
        self.stats['execution_time'] = time.time() - start_time
        
        # Log statistics
        logger.info(f"Analysis completed in {self.stats['execution_time']:.2f} seconds")
        logger.info(f"Total files scanned: {self.stats['total_files_scanned']}")
        logger.info(f"Files with CNPJ occurrences: {self.stats['files_with_cnpj']}")
        logger.info(f"Total CNPJ occurrences found: {self.stats['total_occurrences']}")
        logger.info(f"Ignored files: {self.stats['ignored_files']}")
        
        # Log role statistics
        logger.info("CNPJ roles found:")
        for role, count in self.stats['roles'].items():
            logger.info(f"  {role}: {count}")
            
        logger.info(f"Results exported to {self.output_file}")

def main():
    """Main entry point for the CNPJ analyzer."""
    parser = argparse.ArgumentParser(description='Analyze source code for CNPJ usage patterns')
    
    parser.add_argument('target_folder', help='Target folder to scan')
    parser.add_argument('-o', '--output', default='cnpj_analysis.csv', help='Output CSV file')
    parser.add_argument('-x', '--exclude', nargs='+', help='Directories to exclude')
    parser.add_argument('-m', '--mask', action='store_true', help='Mask CNPJ values')
    parser.add_argument('-s', '--max-size', type=int, default=10*1024*1024, help='Maximum file size in bytes')
    parser.add_argument('-w', '--workers', type=int, default=os.cpu_count(), help='Number of worker processes')
    parser.add_argument('-j', '--java-focus', action='store_true', default=True, help='Focus on Java/Spring patterns')
    parser.add_argument('-y', '--synonyms', action='store_true', default=True, help='Include CNPJ synonyms in search')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Initialize and run the analyzer
    analyzer = CNPJAnalyzer(
        target_folder=args.target_folder,
        output_file=args.output,
        exclude_dirs=args.exclude,
        mask_values=args.mask,
        max_file_size=args.max_size,
        max_workers=args.workers,
        java_focus=args.java_focus,
        include_synonyms=args.synonyms
    )
    
    analyzer.run()

if __name__ == '__main__':
    main()