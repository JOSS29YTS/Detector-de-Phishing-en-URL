import sys
# Configurar codificación UTF-8 para evitar errores con emojis en Windows y otras plataformas
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    pass

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import tldextract
from urllib.parse import urlparse
import whois
from datetime import datetime
import sqlite3
import hashlib
import base64
import os
from dotenv import load_dotenv


# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
CORS(app)

PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

def extract_domain(url):
    """
    Extrae el dominio completo de una URL
    Ejemplo: https://www.ejemplo.com/path → ejemplo.com
    """
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

# Clase de base de datos NORMALIZADA (4NF)
class URLDatabase:
    def __init__(self, db_path='url_analyzer.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Inicializa la base de datos normalizada (4NF)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabla 1: Información INMUTABLE de la URL
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                url_hash TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabla 2: Análisis por fecha (relación 1:N)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER NOT NULL,
                is_malicious BOOLEAN NOT NULL,
                risk_score INTEGER NOT NULL,
                analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (url_id) REFERENCES urls(id),
                UNIQUE(url_id, analysis_date)
            )
        ''')
        
        # Tabla 3: Resultados por fuente (relación 1:N con análisis)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                result BOOLEAN NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES url_analyses(id)
            )
        ''')
        
        # Índices para mejor performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_analyses_url_id ON url_analyses(url_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_analyses_date ON url_analyses(analysis_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_results_analysis_id ON analysis_results(analysis_id)')
        
        conn.commit()
        conn.close()
    
    def get_url_hash(self, url):
        """Genera hash único para la URL"""
        return hashlib.md5(url.encode()).hexdigest()
    
    def _insert_analysis_results(self, cursor, analysis_id, analysis_results):
        for source, result in analysis_results.items():
            if result is not None:
                cursor.execute('''
                    INSERT INTO analysis_results (analysis_id, source, result)
                    VALUES (?, ?, ?)
                ''', (analysis_id, source, bool(result)))
    
    def save_analysis(self, url, is_malicious, risk_score, analysis_results):
        """Guarda análisis en la base de datos normalizada"""
        domain = extract_domain(url)
        url_hash = self.get_url_hash(url)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insertar o obtener la URL
            cursor.execute('''
                INSERT OR IGNORE INTO urls (url, url_hash, domain)
                VALUES (?, ?, ?)
            ''', (url, url_hash, domain))
            
            cursor.execute('SELECT id FROM urls WHERE url_hash = ?', (url_hash,))
            url_id = cursor.fetchone()[0]
            
            # Verificar análisis reciente
            cursor.execute('''
                SELECT id FROM url_analyses 
                WHERE url_id = ? 
                AND analysis_date > datetime('now', '-24 hours')
                LIMIT 1
            ''', (url_id,))
            
            recent_analysis = cursor.fetchone()
            
            if recent_analysis:
                # Actualizar análisis existente
                analysis_id = recent_analysis[0]
                cursor.execute('''
                    UPDATE url_analyses 
                    SET is_malicious = ?, risk_score = ?, analysis_date = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (is_malicious, risk_score, analysis_id))
                
                cursor.execute('DELETE FROM analysis_results WHERE analysis_id = ?', (analysis_id,))
                self._insert_analysis_results(cursor, analysis_id, analysis_results)
                print("💾 Análisis actualizado en base de datos")
            else:
                # Insertar nuevo análisis
                cursor.execute('''
                    INSERT INTO url_analyses (url_id, is_malicious, risk_score)
                    VALUES (?, ?, ?)
                ''', (url_id, is_malicious, risk_score))
                analysis_id = cursor.lastrowid
                self._insert_analysis_results(cursor, analysis_id, analysis_results)
                print("💾 Nuevo análisis guardado en base de datos")
            
            conn.commit()
        
        except Exception as e:
            print(f"❌ Error guardando en BD: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def get_previous_analysis(self, url):
        """Recupera el análisis más reciente de una URL"""
        url_hash = self.get_url_hash(url)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT u.url, ua.is_malicious, ua.risk_score, ua.analysis_date 
                FROM urls u
                JOIN url_analyses ua ON u.id = ua.url_id
                WHERE u.url_hash = ? 
                ORDER BY ua.analysis_date DESC 
                LIMIT 1
            ''', (url_hash,))
            
            result = cursor.fetchone()
            return {
                'url': result[0],
                'is_malicious': bool(result[1]),
                'risk_score': result[2],
                'analysis_date': result[3]
            } if result else None
            
        except Exception as e:
            print(f"❌ Error recuperando análisis: {e}")
            return None
        finally:
            conn.close()
    
    def get_url_history(self, url):
        """Obtiene todos los análisis históricos de una URL"""
        url_hash = self.get_url_hash(url)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT ua.analysis_date, ua.is_malicious, ua.risk_score,
                GROUP_CONCAT(ar.source || ': ' || ar.result) as results
                FROM urls u
                JOIN url_analyses ua ON u.id = ua.url_id
                LEFT JOIN analysis_results ar ON ua.id = ar.analysis_id
                WHERE u.url_hash = ?
                GROUP BY ua.id
                ORDER BY ua.analysis_date DESC
            ''', (url_hash,))
            
            return [{
                'analysis_date': row[0],
                'is_malicious': bool(row[1]),
                'risk_score': row[2],
                'results': row[3]
            } for row in cursor.fetchall()]
            
        except Exception as e:
            print(f"❌ Error obteniendo historial: {e}")
            return []
        finally:
            conn.close()

# Inicializar base de datos
db = URLDatabase()

# Obtener la clase de excepción PywhoisError de forma robusta (evita conflictos de paquetes whois vs python-whois)
PywhoisError = getattr(whois.parser, 'PywhoisError', None) if hasattr(whois, 'parser') else None
if PywhoisError is None:
    PywhoisError = getattr(whois, 'PywhoisError', Exception)

def get_domain_age(domain):
    """
    Obtiene la edad del dominio en días usando WHOIS
    """
    try:
        domain_info = whois.whois(domain)
        
        # Verificar si el dominio existe
        if not domain_info.domain_name:
            print(f"⚠️  Dominio {domain} no está registrado")
            return 0
        
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.strptime(creation_date.split('T')[0], '%Y-%m-%d')
                except ValueError:
                    return 0
            
            age_days = (datetime.now() - creation_date).days
            return max(age_days, 0)
        return 0
        
    except PywhoisError as e:
        if "No match" in str(e):
            print(f"⚠️  Dominio {domain} no encontrado en WHOIS")
            return 0
        else:
            print(f"⚠️  Error WHOIS: {e}")
            return None
    except Exception as e:
        print(f"⚠️  Error obteniendo edad: {e}")
        return None

def check_phish_tank(url):
    """
    Verifica en PhishTank
    """
    try:
        response = requests.post(PHISHTANK_API, data={'url': url, 'format': 'json'}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get('results', {}).get('in_database', False)
        return False
    except Exception as e:
        print(f"Error con PhishTank: {e}")
        return False

def check_virustotal(url):
    """
    Verifica en VirusTotal
    """
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "tu_api_key":
        print("⚠️  Configura tu API key de VirusTotal")
        return False
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        # Codificar URL para API
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        
        # Intentar obtener análisis existente
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            print(f"🔍 VirusTotal: {malicious} motores detectaron malware")
            return malicious > 0
        
        return False
        
    except Exception as e:
        print(f"Error con VirusTotal: {e}")
        return False
    
def extract_advanced_lexical_features(url):
    features = {}
    
    # Palabras clave de phishing
    phishing_keywords = ['login', 'verify', 'secure', 'account', 'banking', 
                        'paypal', 'password', 'update', 'confirm', 'signin']
    features['phishing_keywords_count'] = sum(url.lower().count(keyword) for keyword in phishing_keywords)
    
    domain = extract_domain(url)
    
    # Presencia de digitos en dominio ('0' en lugar de 'o' (typosquatting))
    features['digits_in_domain'] = sum(c.isdigit() for c in domain)
    
    return features

def extract_features(url):
    """
    Extrae características para análisis heurístico
    """
    features = {}
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    features['length'] = len(url) # Longitud total 
    features['num_dots'] = url.count('.') # Número de puntos
    features['num_hyphens'] = url.count('-') # Número de guiones
    features['num_underscore'] = url.count('_') # Número de guiones bajos
    features['has_ip'] = 1 if parsed.netloc.replace('.', '').isdigit() else 0 # Usa IP
    features['is_https'] = 1 if parsed.scheme == 'https' else 0 # Usa HTTPS
    
    # Obtener edad del dominio
    domain = extract_domain(url) 
    domain_age = get_domain_age(domain)
    features['domain_age'] = domain_age if domain_age is not None else 0
    
    # Características adicionales
    features['num_slashes'] = url.count('/') # Número de barras
    features['num_queries'] = url.count('?') # Número de parámetros
    features['num_equals'] = url.count('=') # Número de '='
    features['num_at'] = url.count('@') # Número de '@'
    features['has_port'] = 1 if ':' in parsed.netloc and '/' not in parsed.netloc.split(':')[1] else 0 # Usa puerto
    
    advanced_features = extract_advanced_lexical_features(url)
    features.update(advanced_features)
    
    return features

def calculate_risk_score(features):
    """
    Calcula puntuación de riesgo (0-10)
    """
    
    score = 0
    
    # Dominios no registrados o muy nuevos
    if features['domain_age'] == 0: score += 3         # No registrado
    elif features['domain_age'] < 30: score += 2       # Menos de 1 mes
    
    if features['length'] > 75: score += 1             # Muy larga
    if features['num_hyphens'] > 3: score += 2         # Muchos guiones
    if features['has_ip']: score += 2                  # Usa IP
    if not features['is_https']: score += 2            # No usa HTTPS
    if features['num_equals'] > 3: score += 1          # Muchos parámetros (=)
    
    if features['num_dots'] > 5: score += 1           # Muchos puntos
    if features['num_underscore'] > 2: score += 1     # Muchos guiones bajos
    if features['num_slashes'] > 5: score += 1        # Muchas barras
    if features['num_queries'] > 3: score += 1        # Muchas consultas (?)
    if features['num_at'] > 0: score += 2             # Caracter @ 
    if features['has_port']: score += 1               # Puerto personalizado 
    
    phishing_count = features.get('phishing_keywords_count', 0)
    if phishing_count >= 3:
        score += 3
    elif phishing_count >= 1:
        score += 1
    
    digits_count = features.get('digits_in_domain', 0)
    if digits_count >= 3:
        score += 2
    elif digits_count >= 1:
        score += 1
    
    return min(score, 10) # min limita a 10

def classify_by_heuristics(features):
    """
    Toma de decisiones automática
    Combina todas las características para predicción binaria
    Predice usando reglas heurísticas
    """
    score = calculate_risk_score(features)
    print(f"📊 Puntuación de riesgo: {score}/10")
    return score >= 3 # False -> Segura / True -> Maliciosa

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/virustotal-data', methods=['POST'])
def get_virustotal_data():
    """Obtiene datos detallados de VirusTotal para una URL"""
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL no proporcionada'}), 400
    
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "tu_api_key":
        return jsonify({'error': 'API key de VirusTotal no configurada'}), 500
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        # Codificar URL para API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        
        # Obtener análisis de VirusTotal
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Estadísticas generales
            stats = attributes.get('last_analysis_stats', {})
            total_engines = stats.get('harmless', 0) + stats.get('malicious', 0) + stats.get('suspicious', 0) + stats.get('undetected', 0) + stats.get('timeout', 0)        
            # Resultados por motor
            engine_results = []
            last_analysis_results = attributes.get('last_analysis_results', {})
            
            for engine_name, result_data in last_analysis_results.items():
                engine_results.append({
                    'engine': engine_name,
                    'category': result_data.get('category'),
                    'result': result_data.get('result'),
                    'method': result_data.get('method')
                })
            
            # Ordenar resultados: maliciosos primero, luego sospechosos, luego limpios, luego no detectados
            def engine_sort_key(engine):
                category = engine.get('category', '')
                if category == 'malicious':
                    return 0
                elif category == 'suspicious':
                    return 1
                elif category == 'harmless':
                    return 2
                elif category == 'undetected':
                    return 3
                else:
                    return 4
            
            engine_results.sort(key=engine_sort_key)
            
            return jsonify({
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'total': total_engines,
                'clean': stats.get('harmless', 0),
                'engine_results': engine_results,
                'last_updated': attributes.get('last_modification_date'),
                'reputation': attributes.get('reputation')
            })
        
        elif response.status_code == 404:
            # La URL no ha sido analizada aún, enviarla para análisis
            analysis_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={'url': url},
                timeout=15
            )
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                analysis_id = analysis_data.get('data', {}).get('id')
                
                return jsonify({
                    'status': 'processing',
                    'message': 'El análisis está en proceso. Por favor, actualiza en unos momentos.',
                    'analysis_id': analysis_id
                })
            
            return jsonify({'error': 'No se pudo analizar la URL'}), 404
        
        else:
            return jsonify({'error': 'Error al consultar VirusTotal'}), response.status_code
            
    except Exception as e:
        print(f"Error con VirusTotal: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/analyze', methods=['POST'])
def analyze_url():
    try:
        data = request.json # Traduce la información del json en un diccionario de python
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL no proporcionada'}), 400
        
        # Validar formato de URL
        try:
            from urllib.parse import urlparse
            result = urlparse(url) # https://www.google.com/search?q=python
            if not all([result.scheme, result.netloc]): # result.scheme -> 'https' / result.netloc -> 'www.google.com' 
                return jsonify({'error': 'URL inválida'}), 400
        except:
            return jsonify({'error': 'URL inválida'}), 400
        
        # Consultar APIs
        phish_result = check_phish_tank(url)
        vt_result = check_virustotal(url)
        
        if phish_result or vt_result:
            db.save_analysis(url, True, 10, {
                'PhishTank': phish_result,
                'VirusTotal': vt_result
            })
            return jsonify({
                'url': url,
                'is_malicious': True,
                'risk_score': 10,
                'phish_result': phish_result,
                'virustotal_result': vt_result
            })
        
        # Análisis heurístico
        features = extract_features(url)
        risk_score = calculate_risk_score(features)
        is_suspicious = classify_by_heuristics(features)
        
        # IA EXPLICABLE: Sistema explica sus decisiones
        # Generar razones heurísticas
        heuristic_reasons = []
        
        if features['domain_age'] == 0:  # No registrado
            heuristic_reasons.append("Dominio no registrado")
        elif features['domain_age'] < 30:  # Menos de 1 mes
            heuristic_reasons.append(f"Dominio muy nuevo ({features['domain_age']} días)")
        
        if features['length'] > 75:  # Muy larga
            heuristic_reasons.append(f"URL muy larga ({features['length']} caracteres)")
        
        if features['num_hyphens'] > 3:  # Más de 3 guiones
            heuristic_reasons.append(f"Demasiados guiones en la URL ({features['num_hyphens']})")
        
        if features['has_ip']:  # Usa IP
            heuristic_reasons.append("Usa dirección IP en lugar de dominio")
        
        if not features['is_https']:  # No usa HTTPS
            heuristic_reasons.append("No usa HTTPS (conexión no segura)")
        
        if features['num_equals'] > 3:  # Más de 3 '='
            heuristic_reasons.append(f"Demasiados parámetros en la URL ({features['num_equals']})")
        
        if features['num_at'] > 0:  # Más de 0 '@'
            heuristic_reasons.append("Contiene caracteres '@' sospechosos")
            
        if features['num_dots'] > 5:
            heuristic_reasons.append(f"Demasiados puntos en la URL ({features['num_dots']})")
            
        if features['num_underscore'] > 2:
            heuristic_reasons.append(f"Demasiados guiones bajos ({features['num_underscore']})")
     
        if features['has_port']:
            heuristic_reasons.append("Usa puerto personalizado")
     
        if features['num_slashes'] > 5:
            heuristic_reasons.append(f"URL con muchas rutas ({features['num_slashes']} barras)")
            
        if features['num_queries'] > 3:  
            heuristic_reasons.append(f"Demasiados parámetros de consulta ({features['num_queries']})")
            
        phishing_count = features.get('phishing_keywords_count', 0)
        if phishing_count >= 3:
            heuristic_reasons.append(f"Contiene {phishing_count} palabras clave de phishing")
        elif phishing_count >= 1:
            heuristic_reasons.append("Contiene palabras típicas de phishing")
        
        digits_count = features.get('digits_in_domain', 0)
        if digits_count >= 3:
            heuristic_reasons.append(f"Dominio contiene {digits_count} dígitos")
        elif digits_count >= 1:
            heuristic_reasons.append("Dominio contiene dígitos")
        
        # Guardar en base de datos
        analysis_results = {
            'PhishTank': phish_result,
            'VirusTotal': vt_result,
            'Heuristic': is_suspicious
        }
        
        db.save_analysis(url, is_suspicious, risk_score, analysis_results)
        
        # Obtener edad del dominio
        domain = extract_domain(url)
        domain_age = get_domain_age(domain)
        
        return jsonify({
            'url': url,
            'is_malicious': is_suspicious,
            'risk_score': risk_score,
            'phish_result': phish_result,
            'virustotal_result': vt_result,
            'features': features,
            'domain_age': domain_age or 0,
            'heuristic_reasons': heuristic_reasons
        })
    except Exception as e:
        print(f"❌ Error interno en /analyze: {e}")
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# NUEVA RUTA: Obtener historial de una URL
@app.route('/api/url-history', methods=['POST'])
def get_url_history():
    """Obtiene el historial completo de análisis de una URL"""
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL no proporcionada'}), 400
    
    try:
        history = db.get_url_history(url)
        return jsonify({'url': url, 'history': history})
    
    except Exception as e:
        print(f"❌ Error obteniendo historial: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# RUTA ACTUALIZADA: Estadísticas para la nueva estructura
@app.route('/api/stats')
def get_stats():
    """Obtiene estadísticas generales de la nueva estructura"""
    try:
        conn = sqlite3.connect('url_analyzer.db')
        cursor = conn.cursor()
        
        # URLs únicas analizadas (esto está bien)
        cursor.execute('SELECT COUNT(*) FROM urls')
        total_unique_urls = cursor.fetchone()[0]
        
        # Total de análisis realizados (esto está bien)
        cursor.execute('SELECT COUNT(*) FROM url_analyses')
        total_analyses = cursor.fetchone()[0]
        
        # URLs que han sido maliciosas al menos una vez (esto está bien)
        cursor.execute('''
            SELECT COUNT(DISTINCT u.id) 
            FROM urls u 
            JOIN url_analyses ua ON u.id = ua.url_id 
            WHERE ua.is_malicious = 1
        ''')
        ever_malicious_urls = cursor.fetchone()[0]
        
        # Análisis maliciosos (esto está bien)
        cursor.execute('SELECT COUNT(*) FROM url_analyses WHERE is_malicious = 1')
        malicious_analyses = cursor.fetchone()[0]
        
        # Promedio de riesgo (esto está bien)
        cursor.execute('SELECT AVG(risk_score) FROM url_analyses')
        avg_risk = cursor.fetchone()[0] or 0
        
        # Distribución de riesgo (basada en el ÚLTIMO análisis de cada URL)
        risk_distribution = [0, 0, 0, 0]  # seguro, bajo riesgo, riesgo, malicioso
        cursor.execute('''
            SELECT ua.risk_score 
            FROM url_analyses ua
            JOIN (
                SELECT url_id, MAX(analysis_date) as latest_date
                FROM url_analyses
                GROUP BY url_id
            ) latest ON ua.url_id = latest.url_id AND ua.analysis_date = latest.latest_date
        ''')
        latest_scores = cursor.fetchall()
        for score in latest_scores:
            risk_score = score[0]
            if risk_score <= 2:
                risk_distribution[0] += 1
            elif risk_score <= 4:
                risk_distribution[1] += 1
            elif risk_score <= 7:
                risk_distribution[2] += 1
            else:
                risk_distribution[3] += 1
        
        # Detecciones por fuente (basado en el ÚLTIMO análisis de cada URL)
        source_detections = [0, 0]  # VirusTotal, Heuristic
        cursor.execute('''
            SELECT ar.source, COUNT(*) 
            FROM analysis_results ar
            JOIN url_analyses ua ON ar.analysis_id = ua.id
            JOIN (
                SELECT url_id, MAX(analysis_date) as latest_date
                FROM url_analyses
                GROUP BY url_id
            ) latest ON ua.url_id = latest.url_id AND ua.analysis_date = latest.latest_date
            WHERE ar.result = 1 
            GROUP BY ar.source
        ''')
        sources = cursor.fetchall()
        for source in sources:
            if source[0] == 'VirusTotal':
                source_detections[0] = source[1]
            elif source[0] == 'Heuristic':
                source_detections[1] = source[1]
        
        conn.close()
        
        return jsonify({
            'total_unique_urls': total_unique_urls,
            'total_analyses': total_analyses,
            'ever_malicious_urls': ever_malicious_urls,
            'malicious_analyses': malicious_analyses,
            'avg_risk': avg_risk,
            'risk_distribution': risk_distribution,
            'source_detections': source_detections
        })
    except Exception as e:
        print(f"❌ Error en get_stats: {e}")
        return jsonify({'error': 'Error al obtener estadísticas de la base de datos'}), 500

# RUTA ACTUALIZADA: URLs con análisis más reciente
@app.route('/api/urls')
def get_urls():
    """Obtiene todas las URLs con su análisis más reciente"""
    try:
        conn = sqlite3.connect('url_analyzer.db')
        cursor = conn.cursor()
        
        # Obtener el análisis más reciente por URL
        cursor.execute('''
            SELECT u.url, u.domain, ua.analysis_date, ua.risk_score, ua.is_malicious 
            FROM urls u
            JOIN url_analyses ua ON u.id = ua.url_id
            WHERE ua.analysis_date = (
                SELECT MAX(analysis_date) 
                FROM url_analyses 
                WHERE url_id = u.id
            )
            ORDER BY ua.analysis_date DESC
        ''')
        
        urls = []
        for row in cursor.fetchall():
            url_data = {
                'url': row[0],
                'domain': row[1],
                'analysis_date': row[2],
                'risk_score': row[3],
                'is_malicious': bool(row[4])
            }
            
            # Determinar motor de detección basado en el risk_score
            risk_score = row[3]
            if risk_score >= 0 and risk_score <= 2:
                url_data['detection_engine'] = 'Seguro'
            elif risk_score >= 3 and risk_score <= 9:
                url_data['detection_engine'] = 'Heurístico'
            elif risk_score == 10:
                url_data['detection_engine'] = 'VirusTotal'
            else:
                url_data['detection_engine'] = 'Desconocido'
            
            urls.append(url_data)
        
        conn.close()
        return jsonify({'urls': urls})
    except Exception as e:
        print(f"❌ Error en get_urls: {e}")
        return jsonify({'error': 'Error al obtener URLs de la base de datos'}), 500


# Rutas para las páginas
@app.route('/stats')
def stats_page():
    return render_template('stats.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/api-rest')
def api_rest():
    return render_template('api_rest.html')

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/gdpr')
def gdpr():
    return render_template('gdpr.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)