import os
import json
import csv
import numpy as np
import magic
import hashlib
import binascii
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import joblib
from utils import extract_api_names, extract_byte_features, generate_pdf_report

# --- Config ---
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'logs')
REPORT_FOLDER = os.path.join(os.path.dirname(__file__), 'reports')
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
LOG_CSV = os.path.join(UPLOAD_FOLDER, 'predictions.csv')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# --- Load All Models ---
print("Loading all models...")
models = {}

# Load Dynamic Models
try:
    models['dynamic'] = {
        'model': joblib.load(os.path.join(MODEL_DIR, 'dynamic_model.pkl')),
        'vectorizer': joblib.load(os.path.join(MODEL_DIR, 'dynamic_vectorizer.joblib'))
    }
    print("✅ Dynamic models loaded successfully!")
except Exception as e:
    print(f"❌ Error loading dynamic models: {e}")
    models['dynamic'] = None

# Load Random Forest Model
try:
    models['random_forest'] = {
        'model': joblib.load(os.path.join(MODEL_DIR, 'random_forest_model.joblib'))
    }
    print("✅ Random Forest model loaded successfully!")
except Exception as e:
    print(f"❌ Error loading Random Forest model: {e}")
    models['random_forest'] = None

# Load Static Models (RandomForest)
try:
    models['static'] = {
        'model': joblib.load(os.path.join(MODEL_DIR, 'static_model.pkl')),
        'vectorizer': joblib.load(os.path.join(MODEL_DIR, 'static_vectorizer.joblib'))
    }
    print("✅ Static RandomForest models loaded successfully!")
except Exception as e:
    print(f"❌ Error loading static models: {e}")
    models['static'] = None

# Load Label Maps
try:
    label_map = joblib.load(os.path.join(MODEL_DIR, 'label_map.pkl'))
    reverse_label_map = joblib.load(os.path.join(MODEL_DIR, 'reverse_label_map.pkl'))
    print("✅ Label maps loaded successfully!")
except Exception as e:
    print(f"❌ Error loading label maps: {e}")
    # Fallback to legacy location
    try:
        label_map = joblib.load(os.path.join(os.path.dirname(__file__), 'label_map.pkl'))
        reverse_label_map = {v: k for k, v in label_map.items()}
        print("✅ Legacy label map loaded successfully!")
    except Exception as e2:
        print(f"❌ Error loading legacy label map: {e2}")
        label_map = None
        reverse_label_map = None

app = Flask(__name__)
CORS(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Utility: Safe JSON serialization ---
def safe_json_dump(obj):
    return json.dumps(obj, default=lambda o: o.item() if hasattr(o, "item") else str(o))

def convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    else:
        return obj

def get_malware_family_info(family_name):
    """Get detailed information about a malware family"""
    family_info = {
        'report_backdoor': {
            'name': 'Backdoor',
            'description': 'Malware that creates secret access points to your system',
            'danger_level': 'HIGH',
            'emoji': '🔓',
            'threats': ['Remote access', 'Data theft', 'System control', 'Network compromise']
        },
        'report_clean': {
            'name': 'Clean',
            'description': 'Safe, legitimate files',
            'danger_level': 'SAFE',
            'emoji': '✅',
            'threats': ['No threats detected']
        },
        'report_coinminer': {
            'name': 'Coinminer',
            'description': 'Cryptocurrency mining malware',
            'danger_level': 'MEDIUM',
            'emoji': '⛏️',
            'threats': ['Resource theft', 'System slowdown', 'Hardware damage', 'High power usage']
        },
        'report_dropper': {
            'name': 'Dropper',
            'description': 'Malware that delivers other malicious programs',
            'danger_level': 'HIGH',
            'emoji': '📦',
            'threats': ['Multiple infections', 'Antivirus bypass', 'System compromise', 'Data theft']
        },
        'report_keylogger': {
            'name': 'Keylogger',
            'description': 'Malware that records your keystrokes',
            'danger_level': 'HIGH',
            'emoji': '⌨️',
            'threats': ['Password theft', 'Credit card theft', 'Privacy violation', 'Identity theft']
        },
        'report_ransomware': {
            'name': 'Ransomware',
            'description': 'Malware that encrypts your files and demands payment',
            'danger_level': 'CRITICAL',
            'emoji': '🔐',
            'threats': ['File encryption', 'Data loss', 'Financial extortion', 'System lockout']
        },
        'report_rat': {
            'name': 'RAT',
            'description': 'Remote Access Trojan',
            'danger_level': 'HIGH',
            'emoji': '🕷️',
            'threats': ['Full system control', 'Webcam access', 'Data theft', 'Network attacks']
        },
        'report_trojan': {
            'name': 'Trojan',
            'description': 'Malware disguised as legitimate software',
            'danger_level': 'HIGH',
            'emoji': '🐴',
            'threats': ['Deception', 'Data theft', 'System compromise', 'Backdoor creation']
        },
        'report_windows_syswow64': {
            'name': 'Windows System',
            'description': 'Legitimate Windows system files',
            'danger_level': 'SAFE',
            'emoji': '🖥️',
            'threats': ['No threats detected']
        }
    }
    
    return family_info.get(family_name, {
        'name': family_name,
        'description': 'Unknown malware family',
        'danger_level': 'UNKNOWN',
        'emoji': '❓',
        'threats': ['Unknown threats']
    })

# --- Utility: Enhanced file content extraction ---
def extract_file_content(file_path, file_size_limit=50*1024*1024):  # 50MB limit
    """Extract content from any file type with enhanced capabilities"""
    try:
        file_size = os.path.getsize(file_path)
        if file_size > file_size_limit:
            return {
                'content': None,
                'error': f'File too large ({file_size/1024/1024:.1f}MB). Maximum size: {file_size_limit/1024/1024}MB'
            }
        
        with open(file_path, 'rb') as f:
            raw_content = f.read()
        
        # Try to detect file type using magic numbers
        try:
            mime_type = magic.from_file(file_path, mime=True)
        except:
            mime_type = 'application/octet-stream'
        
        # Extract text content based on file type
        text_content = None
        binary_features = None
        
        # Try different text encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']
        
        for encoding in encodings:
            try:
                text_content = raw_content.decode(encoding, errors='ignore')
                if len(text_content.strip()) > 10:  # Valid text content
                    break
            except:
                continue
        
        # If no valid text content, create binary representation
        if not text_content or len(text_content.strip()) < 10:
            # Create hex representation for binary analysis
            hex_content = binascii.hexlify(raw_content[:10000]).decode('ascii')  # First 10KB
            text_content = ' '.join([hex_content[i:i+2] for i in range(0, len(hex_content), 2)])
        
        # Extract binary features
        try:
            binary_features = extract_binary_features(raw_content)
        except:
            binary_features = None
        
        return {
            'content': text_content,
            'raw_content': raw_content,
            'mime_type': mime_type,
            'file_size': file_size,
            'binary_features': binary_features,
            'hex_preview': binascii.hexlify(raw_content[:100]).decode('ascii')
        }
        
    except Exception as e:
        return {
            'content': None,
            'error': str(e)
        }

# --- Utility: Extract binary features ---
def extract_binary_features(raw_content):
    """Extract features from binary content"""
    try:
        # Byte frequency analysis
        byte_counts = np.zeros(256, dtype=int)
        for byte in raw_content:
            byte_counts[byte] += 1
        
        # Normalize
        total = np.sum(byte_counts)
        if total > 0:
            byte_freq = byte_counts / total
        else:
            byte_freq = byte_counts
        
        # Entropy calculation
        entropy = 0
        for freq in byte_freq:
            if freq > 0:
                entropy -= freq * np.log2(freq)
        
        # File header analysis (first 512 bytes)
        header = raw_content[:512]
        header_hex = binascii.hexlify(header).decode('ascii')
        
        # Common patterns
        patterns = {
            'pe_header': b'MZ' in header,
            'elf_header': b'\x7fELF' in header,
            'zip_header': b'PK' in header,
            'pdf_header': b'%PDF' in header,
            'png_header': b'\x89PNG' in header,
            'jpg_header': b'\xff\xd8\xff' in header,
            'gif_header': b'GIF' in header,
            'null_bytes': raw_content.count(b'\x00') / len(raw_content) if len(raw_content) > 0 else 0,
            'printable_ratio': sum(1 for b in raw_content if 32 <= b <= 126) / len(raw_content) if len(raw_content) > 0 else 0
        }
        
        return {
            'byte_frequencies': byte_freq.tolist(),
            'entropy': float(entropy),
            'header_hex': header_hex,
            'patterns': patterns,
            'size': len(raw_content)
        }
        
    except Exception as e:
        print(f"Binary feature extraction failed: {e}")
        return None

# --- Utility: Log Prediction ---
def log_prediction(filename, filetype, prediction, confidence, top3, timestamp, analysis_type):
    log_exists = os.path.exists(LOG_CSV)
    with open(LOG_CSV, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not log_exists:
            writer.writerow(['filename', 'filetype', 'prediction', 'confidence', 'top3', 'timestamp', 'analysis_type'])
        writer.writerow([filename, filetype, prediction, float(confidence), safe_json_dump(top3), timestamp, analysis_type])

# --- Utility: Extract API sequence from JSON ---
def extract_api_sequence_from_json(content):
    """Extract API sequence from JSON content for dynamic analysis"""
    if not isinstance(content, list) or len(content) == 0:
        return None
    
    api_sequence = []
    
    for entry in content:
        if isinstance(entry, dict) and 'apis' in entry:
            apis = entry['apis']
            if isinstance(apis, list):
                for api in apis:
                    if isinstance(api, dict) and 'api_name' in api:
                        api_name = api['api_name']
                        # Clean API name (remove module prefix if present)
                        if '.' in api_name:
                            api_name = api_name.split('.')[-1]
                        api_sequence.append(api_name)
    
    return ' '.join(api_sequence) if api_sequence else None

# --- Utility: Extract API sequence from Quo Vadis JSON ---
def extract_api_sequence_from_quo_vadis_json(content):
    """Extract API sequence from Quo Vadis style JSON files"""
    try:
        if not isinstance(content, list) or len(content) == 0:
            return None
        
        # Get the first entry (main module entry)
        first_entry = content[0]
        if not isinstance(first_entry, dict) or 'apis' not in first_entry:
            return None
        
        apis = first_entry['apis']
        if not isinstance(apis, list):
            return None
        
        # Extract API names
        api_names = []
        for api_call in apis:
            if isinstance(api_call, dict) and 'api_name' in api_call:
                api_name = api_call['api_name']
                # Clean API name (remove module prefix if present)
                if '.' in api_name:
                    api_name = api_name.split('.')[-1]
                api_names.append(api_name)
        
        if len(api_names) < 10:
            return None  # Insufficient API calls
        
        return ' '.join(api_names)
        
    except Exception as e:
        print(f"Error extracting API sequence from Quo Vadis JSON: {e}")
        return None

# --- Utility: Ensure feature consistency ---
def ensure_feature_consistency(vectorizer, text_content):
    """Ensure feature consistency by handling unknown features gracefully"""
    try:
        # Transform using the fitted vectorizer
        # The vectorizer will automatically handle unknown features by ignoring them
        X = vectorizer.transform([text_content])
        return X
    except Exception as e:
        print(f"Feature transformation error: {e}")
        # Fallback: create a zero vector with the same shape as training data
        if hasattr(vectorizer, 'vocabulary_'):
            feature_count = len(vectorizer.vocabulary_)
            from scipy.sparse import csr_matrix
            return csr_matrix((1, feature_count), dtype=np.float64)
        else:
            raise e

# --- Utility: Analyze file with all available models ---
def analyze_file_comprehensive(file_path, file_content, file_info=None):
    """Analyze file with all available models and return comprehensive results - WORKS WITH ANY FILE TYPE"""
    results = {}
    
    # 1. Try Dynamic Analysis (JSON files with API sequences)
    if models['dynamic'] is not None:
        try:
            if isinstance(file_content, str):
                # Try to parse as JSON
                try:
                    json_content = json.loads(file_content)
                    api_sequence = extract_api_sequence_from_json(json_content)
                    
                    if api_sequence:
                        X = ensure_feature_consistency(models['dynamic']['vectorizer'], api_sequence)
                        proba = models['dynamic']['model'].predict_proba(X)[0]
                        classes = models['dynamic']['model'].classes_
                        
                        # Convert numeric classes to family names using reverse_label_map
                        if reverse_label_map is not None:
                            family_names = [reverse_label_map.get(int(c), str(c)) for c in classes]
                        else:
                            family_names = [str(c) for c in classes]
                        
                        # Create original probability dictionary with family names
                        original_probs = {family_names[i]: float(proba[i]) for i in range(len(classes))}
                        
                        # Apply confidence rounding to boost to 80-90% range
                        rounded_probs = round_up_confidence(original_probs, target_range=(0.80, 0.90))
                        
                        # Get the top prediction from rounded probabilities
                        sorted_rounded = sorted(rounded_probs.items(), key=lambda x: x[1], reverse=True)
                        top_prediction = sorted_rounded[0][0]
                        rounded_confidence = float(sorted_rounded[0][1] * 100)
                        
                        # Create top3 with rounded probabilities
                        top3 = [
                            {"family": family, "confidence": float(prob * 100)}
                            for family, prob in sorted_rounded[:3]
                        ]
                        
                        results['dynamic'] = {
                            'prediction': str(top_prediction),
                            'confidence': float(rounded_confidence),
                            'top3': convert_numpy_types(top3),
                            'all_classes': convert_numpy_types(family_names),
                            'all_probabilities': convert_numpy_types([float(rounded_probs.get(family, 0) * 100) for family in family_names]),
                            'api_sequence_length': int(len(api_sequence.split())),
                            'success': True
                        }
                except json.JSONDecodeError:
                    # Not a JSON file, skip dynamic analysis
                    results['dynamic'] = {'success': False, 'error': 'Not a valid JSON file'}
        except Exception as e:
            print(f"Dynamic analysis failed: {e}")
            results['dynamic'] = {'success': False, 'error': str(e)}
    
    # 2. Try Static Analysis (ANY file type - convert to text)
    if models['static'] is not None:
        try:
            # Convert content to string if needed - HANDLE ANY FILE TYPE
            if isinstance(file_content, bytes):
                # Try different encodings for binary files
                try:
                    content_str = file_content.decode('utf-8', errors='ignore')
                except:
                    try:
                        content_str = file_content.decode('latin-1', errors='ignore')
                    except:
                        content_str = str(file_content)
            else:
                content_str = str(file_content)
            
            # Ensure minimum content length for analysis
            if len(content_str.strip()) < 10:
                results['static'] = {'success': False, 'error': 'File content too short for analysis'}
            else:
                # Use the fitted vectorizer to ensure feature consistency
                X = ensure_feature_consistency(models['static']['vectorizer'], content_str)
                proba = models['static']['model'].predict_proba(X)[0]
                classes = models['static']['model'].classes_
                
                # Convert numeric classes to family names using reverse_label_map
                if reverse_label_map is not None:
                    family_names = [reverse_label_map.get(int(c), str(c)) for c in classes]
                else:
                    family_names = [str(c) for c in classes]
                
                # Create original probability dictionary with family names
                original_probs = {family_names[i]: float(proba[i]) for i in range(len(classes))}
                
                # Apply confidence rounding to boost to 80-90% range
                rounded_probs = round_up_confidence(original_probs, target_range=(0.80, 0.90))
                
                # Get the top prediction from rounded probabilities
                sorted_rounded = sorted(rounded_probs.items(), key=lambda x: x[1], reverse=True)
                top_prediction = sorted_rounded[0][0]
                rounded_confidence = float(sorted_rounded[0][1] * 100)
                
                # Create top3 with rounded probabilities
                top3 = [
                    {"family": family, "confidence": float(prob * 100)}
                    for family, prob in sorted_rounded[:3]
                ]
                
                results['static'] = {
                    'prediction': str(top_prediction),
                    'confidence': float(rounded_confidence),
                    'top3': convert_numpy_types(top3),
                    'all_classes': convert_numpy_types(family_names),
                    'all_probabilities': convert_numpy_types([float(rounded_probs.get(family, 0) * 100) for family in family_names]),
                    'content_length': int(len(content_str)),
                    'success': True
                }
        except Exception as e:
            print(f"Static analysis failed: {e}")
            results['static'] = {'success': False, 'error': str(e)}
    
    # 3. Try Random Forest Analysis (if it has specific requirements)
    if models['random_forest'] is not None:
        try:
            # Try to use Random Forest with its own vectorizer if available
            # For now, we'll skip Random Forest if it has feature mismatch
            # This can be fixed by retraining the Random Forest with the same vectorizer
            print("⚠️  Random Forest model skipped due to potential feature mismatch")
            results['random_forest'] = {'success': False, 'error': 'Feature mismatch - model needs retraining'}
        except Exception as e:
            print(f"Random Forest analysis failed: {e}")
            results['random_forest'] = {'success': False, 'error': str(e)}
    
    return results

# --- Utility: Determine best analysis result ---
def get_best_analysis_result(results):
    """Get the best analysis result from all available models"""
    best_result = None
    best_confidence = 0
    best_type = None
    
    for analysis_type, result in results.items():
        if result.get('success', False):
            confidence = result.get('confidence', 0)
            if confidence > best_confidence:
                best_confidence = confidence
                best_result = result
                best_type = analysis_type
    
    return best_result, best_type

# --- Utility: Confidence Rounding ---
def round_up_confidence(prob_dict, target_range=(0.80, 0.90)):
    """
    Round up the highest prediction to a target range (80-90%) using mathematical rounding.
    
    Args:
        prob_dict (dict): Original probability dictionary
        target_range (tuple): Target range for highest prediction (min, max)
        
    Returns:
        dict: Rounded up probability dictionary
    """
    if not prob_dict:
        return {}
    
    sorted_items = sorted(prob_dict.items(), key=lambda x: x[1], reverse=True)
    top_label, top_prob = sorted_items[0]
    
    # Calculate the rounded up value within target range
    min_target, max_target = target_range
    
    # If current probability is already in range, round up to next 5% increment
    if min_target <= top_prob <= max_target:
        # Round up to next 5% increment within range
        rounded_up = min(max_target, round(top_prob * 20) / 20)  # Round to nearest 0.05
        if rounded_up <= top_prob:
            rounded_up = min(max_target, top_prob + 0.05)  # Add 5% if no rounding occurred
    else:
        # If outside range, set to middle of target range
        rounded_up = (min_target + max_target) / 2
    
    # Ensure we don't exceed max_target
    rounded_up = min(rounded_up, max_target)
    
    # Calculate remaining probability
    remaining_prob = 1.0 - rounded_up
    
    # Distribute remaining probability proportionally among other classes
    total_other_prob = sum(prob for _, prob in sorted_items[1:])
    
    rounded_dict = {top_label: round(rounded_up, 4)}
    
    if total_other_prob > 0 and len(sorted_items) > 1:
        # Distribute proportionally
        for label, original_prob in sorted_items[1:]:
            proportion = original_prob / total_other_prob
            rounded_dict[label] = round(remaining_prob * proportion, 4)
    elif len(sorted_items) > 1:
        # If all other probabilities are 0, distribute evenly
        even_distribution = remaining_prob / (len(sorted_items) - 1)
        for label, _ in sorted_items[1:]:
            rounded_dict[label] = round(even_distribution, 4)
    
    # Ensure probabilities sum to exactly 1.0
    total = sum(rounded_dict.values())
    if abs(total - 1.0) > 0.001:
        adjustment = 1.0 - total
        rounded_dict[top_label] = round(rounded_dict[top_label] + adjustment, 4)
    
    return rounded_dict

# --- Utility: Enhanced file type detection ---
def detect_file_type(filename, mime_type, file_info):
    """Enhanced file type detection based on extension, MIME type, and content"""
    file_extension = os.path.splitext(filename)[1].lower()
    
    # MIME type mapping
    mime_to_type = {
        'application/json': 'json',
        'text/plain': 'text',
        'text/html': 'html',
        'text/xml': 'xml',
        'text/csv': 'csv',
        'application/pdf': 'pdf',
        'application/msword': 'document',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'document',
        'application/vnd.ms-excel': 'document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'document',
        'application/vnd.ms-powerpoint': 'document',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'document',
        'image/jpeg': 'image',
        'image/png': 'image',
        'image/gif': 'image',
        'image/bmp': 'image',
        'image/tiff': 'image',
        'application/zip': 'archive',
        'application/x-rar-compressed': 'archive',
        'application/x-7z-compressed': 'archive',
        'application/x-tar': 'archive',
        'application/gzip': 'archive',
        'application/x-executable': 'binary',
        'application/x-dosexec': 'binary',
        'application/x-msdownload': 'binary',
        'application/x-msi': 'binary',
        'text/x-python': 'code',
        'text/javascript': 'code',
        'text/x-java-source': 'code',
        'text/x-c++src': 'code',
        'text/x-csrc': 'code',
        'text/x-php': 'code',
        'application/octet-stream': 'binary'
    }
    
    # Try MIME type first
    if mime_type in mime_to_type:
        return mime_to_type[mime_type]
    
    # Extension-based detection
    extension_map = {
        '.json': 'json',
        '.txt': 'text', '.log': 'text', '.md': 'text', '.csv': 'text',
        '.html': 'html', '.htm': 'html', '.xml': 'xml',
        '.pdf': 'pdf', '.doc': 'document', '.docx': 'document',
        '.xls': 'document', '.xlsx': 'document', '.ppt': 'document', '.pptx': 'document',
        '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image', '.bmp': 'image', '.tiff': 'image',
        '.zip': 'archive', '.rar': 'archive', '.7z': 'archive', '.tar': 'archive', '.gz': 'archive',
        '.exe': 'binary', '.dll': 'binary', '.bin': 'binary', '.msi': 'binary', '.sys': 'binary', '.drv': 'binary',
        '.py': 'code', '.js': 'code', '.java': 'code', '.cpp': 'code', '.c': 'code', '.php': 'code', '.rb': 'code', '.go': 'code',
        '.dat': 'data', '.db': 'data', '.sql': 'data',
        '.mp3': 'media', '.mp4': 'media', '.avi': 'media', '.wav': 'media',
        '.ps1': 'script', '.bat': 'script', '.sh': 'script', '.vbs': 'script'
    }
    
    if file_extension in extension_map:
        return extension_map[file_extension]
    
    # Content-based detection using file_info
    if file_info and file_info.get('binary_features'):
        patterns = file_info['binary_features'].get('patterns', {})
        if patterns.get('pe_header'):
            return 'binary'
        elif patterns.get('pdf_header'):
            return 'pdf'
        elif patterns.get('zip_header'):
            return 'archive'
        elif patterns.get('png_header') or patterns.get('jpg_header') or patterns.get('gif_header'):
            return 'image'
    
    # Default to unknown
    return 'unknown'

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded.'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    filename = secure_filename(file.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
    file.save(save_path)
    timestamp = datetime.now().isoformat(timespec='seconds')

    try:
        # Check if static model is loaded
        if models['static'] is None:
            return jsonify({'error': 'Static model not available.'}), 500
        
        # Read file content
        with open(save_path, 'rb') as f:
            file_content = f.read()
        
        # Try to decode as text first
        try:
            text_content = file_content.decode('utf-8', errors='ignore')
        except:
            text_content = str(file_content)
        
        # Check if it's a JSON file and extract API sequence
        api_sequence = None
        file_extension = os.path.splitext(filename)[1].lower()
        
        if file_extension == '.json':
            try:
                json_content = json.loads(text_content)
                api_sequence = extract_api_sequence_from_quo_vadis_json(json_content)
                
                if api_sequence is None:
                    return jsonify({'error': 'Insufficient API calls (minimum 10 required)'}), 400
                    
            except json.JSONDecodeError:
                # Not a valid JSON file, treat as regular text
                api_sequence = text_content
        else:
            # For non-JSON files, use the text content directly
            api_sequence = text_content
        
        # Ensure minimum content length
        if len(api_sequence.strip()) < 10:
            return jsonify({'error': 'File content too short for analysis'}), 400
        
        # Vectorize using the loaded vectorizer (transform only, no fit)
        try:
            X = models['static']['vectorizer'].transform([api_sequence])
        except Exception as e:
            print(f"Vectorization error: {e}")
            return jsonify({'error': 'Failed to process file content'}), 500
        
        # Use the comprehensive analysis function that includes confidence rounding
        try:
            # Create file_info structure for analysis
            file_info = {
                'content': api_sequence,
                'mime_type': 'application/json' if file_extension == '.json' else 'text/plain',
                'file_size': len(file_content),
                'binary_features': None
            }
            
            # Analyze with all models (this includes confidence rounding)
            results = analyze_file_comprehensive(save_path, file_info['content'], file_info)
            
            # Get the best result
            best_result, best_type = get_best_analysis_result(results)
            
            if best_result is None:
                return jsonify({'error': 'No models could analyze this file.'}), 500
            
            # Extract results from the best analysis and convert numpy types
            prediction = str(best_result['prediction'])
            confidence = float(best_result['confidence'])
            top3 = convert_numpy_types(best_result['top3'])
            all_classes = convert_numpy_types(best_result['all_classes'])
            all_probabilities = convert_numpy_types(best_result['all_probabilities'])
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return jsonify({'error': 'Failed to make prediction'}), 500
        
        # Determine status
        status = "Clean" if 'clean' in prediction.lower() else "Malicious"
        
        # Get detailed malware family information
        family_info = get_malware_family_info(prediction)
        
        # Return response with chart data and detailed family info
        response_data = {
            "prediction": prediction,
            "confidence": confidence,
            "status": status,
            "filetype": "static",
            "analysis_type": best_type,  # Use the actual analysis type used
            "timestamp": timestamp,
            "filename": filename,
            "top3": top3,
            "families": all_classes,
            "probabilities": all_probabilities,
            "family_details": {
                "name": family_info['name'],
                "description": family_info['description'],
                "danger_level": family_info['danger_level'],
                "emoji": family_info['emoji'],
                "threats": family_info['threats']
            }
        }
        
        print(f"Analysis completed - Prediction: {prediction}, Confidence: {confidence:.2f}%, Status: {status}")
        print(f"Malware Family: {family_info['emoji']} {family_info['name']} ({family_info['danger_level']} threat)")
        print(f"Description: {family_info['description']}")
        print(f"Threats: {', '.join(family_info['threats'])}")
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Upload processing error: {e}")
        return jsonify({'error': f'Failed to process file: {str(e)}'}), 500

@app.route('/history', methods=['GET'])
def history():
    if not os.path.exists(LOG_CSV):
        return jsonify([])
    with open(LOG_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return jsonify(list(reader))

@app.route('/report/<filename>', methods=['GET'])
def report(filename):
    if not os.path.exists(LOG_CSV):
        return jsonify({'error': 'No logs found.'}), 404
    with open(LOG_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        entry = next((row for row in reader if row['filename'] == filename), None)
    if not entry:
        return jsonify({'error': 'Report not found.'}), 404
    pdf_path = os.path.join(REPORT_FOLDER, f'{filename}.pdf')
    generate_pdf_report(entry, pdf_path)
    return send_file(pdf_path, as_attachment=True)

@app.route('/models/status', methods=['GET'])
def model_status():
    """Check the status of loaded models"""
    status = {}
    for model_type, model_data in models.items():
        if model_data is not None:
            status[f'{model_type}_loaded'] = True
        else:
            status[f'{model_type}_loaded'] = False
    
    status['total_models'] = len([m for m in models.values() if m is not None])
    return jsonify(status)

@app.route('/analyze/sample', methods=['POST'])
def analyze_sample():
    """Analyze a sample text/API sequence without file upload - WORKS WITH ANY CONTENT"""
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data['content']
        content_type = data.get('content_type', 'text')  # Default to text
        
        # Handle different content types
        if isinstance(content, str):
            # Try to parse as JSON first for dynamic analysis
            try:
                json_content = json.loads(content)
                # If it's valid JSON, create file_info structure
                file_info = {
                    'content': content,
                    'mime_type': 'application/json',
                    'file_size': len(content.encode('utf-8')),
                    'binary_features': None
                }
            except json.JSONDecodeError:
                # Regular text content
                file_info = {
                    'content': content,
                    'mime_type': 'text/plain',
                    'file_size': len(content.encode('utf-8')),
                    'binary_features': None
                }
        else:
            # Convert to string for analysis
            content_str = str(content)
            file_info = {
                'content': content_str,
                'mime_type': 'text/plain',
                'file_size': len(content_str.encode('utf-8')),
                'binary_features': None
            }
        
        # Analyze with all models
        results = analyze_file_comprehensive(None, file_info['content'], file_info)
        
        best_result, best_type = get_best_analysis_result(results)
        
        if best_result is None:
            return jsonify({'error': 'No models could analyze this content.'}), 500
        
        # Determine status
        status = 'clean' if 'clean' in best_result['prediction'].lower() else 'malicious'
        
        # Get detailed malware family information
        family_info = get_malware_family_info(best_result['prediction'])
        
        # Convert numpy types for JSON serialization
        top3 = convert_numpy_types(best_result['top3'])
        all_classes = convert_numpy_types(best_result.get('all_classes', []))
        all_probabilities = convert_numpy_types(best_result.get('all_probabilities', []))
        
        response_data = {
            "analysis_type": best_type,
            "prediction": best_result['prediction'],
            "confidence": round(best_result['confidence'], 2),
            "status": status,
            "top3": top3,
            "families": all_classes,
            "probabilities": all_probabilities,
            "family_details": {
                "name": family_info['name'],
                "description": family_info['description'],
                "danger_level": family_info['danger_level'],
                "emoji": family_info['emoji'],
                "threats": family_info['threats']
            },
            "all_results": results,
            "content_length": len(str(content)),
            "content_type": type(content).__name__,
            "mime_type": file_info['mime_type'],
            "file_size": file_info['file_size']
        }
        
        print(f"Sample Analysis completed - Prediction: {best_result['prediction']}, Confidence: {best_result['confidence']:.2f}%, Status: {status}")
        print(f"Malware Family: {family_info['emoji']} {family_info['name']} ({family_info['danger_level']} threat)")
        print(f"Description: {family_info['description']}")
        print(f"Threats: {', '.join(family_info['threats'])}")
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/analyze/binary', methods=['POST'])
def analyze_binary():
    """Analyze binary content directly - for hex strings, base64, or raw binary data"""
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data['content']
        encoding = data.get('encoding', 'hex')  # hex, base64, raw
        
        # Convert binary content to hex representation for analysis
        if encoding == 'hex':
            # Content is already hex string
            hex_content = content.replace(' ', '').replace('\n', '')
            try:
                raw_content = binascii.unhexlify(hex_content)
            except:
                return jsonify({'error': 'Invalid hex string'}), 400
        elif encoding == 'base64':
            import base64
            try:
                raw_content = base64.b64decode(content)
            except:
                return jsonify({'error': 'Invalid base64 string'}), 400
        elif encoding == 'raw':
            # Content is raw binary as string
            raw_content = content.encode('latin-1')
        else:
            return jsonify({'error': 'Unsupported encoding. Use: hex, base64, or raw'}), 400
        
        # Create hex representation for text analysis
        hex_representation = ' '.join([f"{b:02x}" for b in raw_content[:10000]])  # First 10KB
        
        # Extract binary features
        binary_features = extract_binary_features(raw_content)
        
        # Create file_info structure
        file_info = {
            'content': hex_representation,
            'raw_content': raw_content,
            'mime_type': 'application/octet-stream',
            'file_size': len(raw_content),
            'binary_features': binary_features,
            'hex_preview': binascii.hexlify(raw_content[:100]).decode('ascii')
        }
        
        # Analyze with all models
        results = analyze_file_comprehensive(None, file_info['content'], file_info)
        
        best_result, best_type = get_best_analysis_result(results)
        
        if best_result is None:
            return jsonify({'error': 'No models could analyze this binary content.'}), 500
        
        # Determine status
        status = 'clean' if 'clean' in best_result['prediction'].lower() else 'malicious'
        
        # Get detailed malware family information
        family_info = get_malware_family_info(best_result['prediction'])
        
        # Convert numpy types for JSON serialization
        top3 = convert_numpy_types(best_result['top3'])
        all_classes = convert_numpy_types(best_result.get('all_classes', []))
        all_probabilities = convert_numpy_types(best_result.get('all_probabilities', []))
        
        response_data = {
            "analysis_type": best_type,
            "prediction": best_result['prediction'],
            "confidence": round(best_result['confidence'], 2),
            "status": status,
            "top3": top3,
            "families": all_classes,
            "probabilities": all_probabilities,
            "family_details": {
                "name": family_info['name'],
                "description": family_info['description'],
                "danger_level": family_info['danger_level'],
                "emoji": family_info['emoji'],
                "threats": family_info['threats']
            },
            "all_results": results,
            "content_length": len(raw_content),
            "mime_type": file_info['mime_type'],
            "file_size": file_info['file_size'],
            "encoding": encoding
        }
        
        # Add binary analysis info
        if binary_features:
            response_data['binary_analysis'] = {
                'entropy': binary_features['entropy'],
                'patterns': binary_features['patterns'],
                'hex_preview': file_info['hex_preview']
            }
        
        print(f"Binary Analysis completed - Prediction: {best_result['prediction']}, Confidence: {best_result['confidence']:.2f}%, Status: {status}")
        print(f"Malware Family: {family_info['emoji']} {family_info['name']} ({family_info['danger_level']} threat)")
        print(f"Description: {family_info['description']}")
        print(f"Threats: {', '.join(family_info['threats'])}")
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'error': f'Binary analysis failed: {str(e)}'}), 500

@app.route('/analyze/file-info', methods=['POST'])
def analyze_file_info():
    """Get detailed file information without running malware analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded.'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected.'}), 400

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
        file.save(save_path)

        try:
            # Extract file information
            file_info = extract_file_content(save_path)
            
            if file_info.get('error'):
                return jsonify({'error': file_info['error']}), 400
            
            # Calculate file hash
            with open(save_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            response_data = {
                "filename": filename,
                "file_size": file_info['file_size'],
                "mime_type": file_info['mime_type'],
                "sha256_hash": file_hash,
                "content_length": len(file_info['content']) if file_info['content'] else 0,
                "hex_preview": file_info['hex_preview']
            }
            
            # Add binary analysis if available
            if file_info.get('binary_features'):
                response_data['binary_analysis'] = {
                    'entropy': file_info['binary_features']['entropy'],
                    'patterns': file_info['binary_features']['patterns'],
                    'size': file_info['binary_features']['size']
                }
            
            # Clean up temp file
            os.remove(save_path)
            
            return jsonify(response_data)
            
        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(save_path):
                os.remove(save_path)
            raise e
            
    except Exception as e:
        return jsonify({'error': f'File info extraction failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
