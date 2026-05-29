import requests
import time
import csv
import sqlite3
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Configuración - ACTUALIZADA para la nueva BD 4NF
FLASK_APP_URL = "http://localhost:5000/analyze"
URLS_FILE = "urls_to_analyze.csv"  # Archivo con las URLs a analizar
DATABASE_PATH = "url_analyzer.db"  # MISMA base de datos (ahora 4NF)
MAX_THREADS = 3  # Número máximo de hilos paralelos (conservador)
DELAY_BETWEEN_REQUESTS = 0.5  # Segundos entre solicitudes

# FUNCIONES COMPATIBLES con la NUEVA estructura de BD 4NF
def get_url_hash(url):
    """Genera hash único para la URL - MISMA función que en tu app.py"""
    return hashlib.md5(url.encode()).hexdigest()

def extract_domain(url):
    """
    Extrae el dominio completo de una URL - MISMA función que en tu app.py
    Ejemplo: https://www.ejemplo.com/path → ejemplo.com
    """
    import tldextract
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def read_urls_from_file(file_path):
    """
    Lee URLs desde un archivo CSV o TXT
    Formato CSV: columna 'url' con las URLs
    Formato TXT: una URL por línea
    """
    urls = []
    try:
        if file_path.endswith('.csv'):
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if 'url' in row and row['url'].strip():
                        urls.append(row['url'].strip())
        else:
            with open(file_path, 'r', encoding='utf-8') as file:
                urls = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error leyendo archivo: {e}")
    return urls

def url_exists_in_db(url, conn):
    """
    Verifica si la URL ya existe en la BD - ACTUALIZADA para 4NF
    """
    url_hash = get_url_hash(url)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM urls WHERE url_hash = ?', (url_hash,))
    result = cursor.fetchone()
    return result is not None

def analyze_single_url(url):
    """
    Envía una URL individual al endpoint de análisis
    """
    try:
        # Validar formato de URL primero (igual que en tu app.py)
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            print(f"❌ URL inválida: {url}")
            return False
            
        response = requests.post(
            FLASK_APP_URL,
            json={'url': url},
            timeout=30
        )
        
        if response.status_code == 200:
            result_data = response.json()
            risk_score = result_data.get('risk_score', 'N/A')
            is_malicious = result_data.get('is_malicious', False)
            status = "MALICIOSA" if is_malicious else "LIMPIA"
            print(f"✅ Analizada: {url} - Riesgo: {risk_score} - {status}")
            return True
        else:
            print(f"❌ Error {response.status_code} con {url}: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Excepción con {url}: {str(e)}")
        return False

def get_db_connection():
    """Conexión a la base de datos SQLite - MISMA BD que tu app.py"""
    return sqlite3.connect(DATABASE_PATH)

def get_existing_urls():
    """
    Obtiene todas las URLs ya existentes en la BD - ACTUALIZADA para 4NF
    """
    existing_urls = set()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM urls")
        existing_urls = {row[0] for row in cursor.fetchall()}
        conn.close()
    except Exception as e:
        print(f"⚠️  Error obteniendo URLs existentes: {e}")
    return existing_urls

def process_urls_batch(urls_batch):
    """
    Procesa un lote de URLs
    """
    successful = 0
    for url in urls_batch:
        if analyze_single_url(url):
            successful += 1
        time.sleep(DELAY_BETWEEN_REQUESTS)
    return successful

def export_statistics():
    """
    Exporta estadísticas desde la base de datos - COMPLETAMENTE ACTUALIZADA para 4NF
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ===== ESTADÍSTICAS ACTUALIZADAS PARA LA NUEVA ESTRUCTURA 4NF =====
        
        # 1. URLs únicas analizadas
        cursor.execute("SELECT COUNT(*) FROM urls")
        total_unique_urls = cursor.fetchone()[0]
        
        # 2. Total de análisis realizados (puede haber múltiples por URL)
        cursor.execute("SELECT COUNT(*) FROM url_analyses")
        total_analyses = cursor.fetchone()[0]
        
        # 3. URLs que han sido maliciosas al menos una vez
        cursor.execute('''
            SELECT COUNT(DISTINCT u.id) 
            FROM urls u 
            JOIN url_analyses ua ON u.id = ua.url_id 
            WHERE ua.is_malicious = 1
        ''')
        ever_malicious_urls = cursor.fetchone()[0]
        
        # 4. Análisis maliciosos (puede incluir múltiples de una misma URL)
        cursor.execute('SELECT COUNT(*) FROM url_analyses WHERE is_malicious = 1')
        malicious_analyses = cursor.fetchone()[0]
        
        # 5. Promedio de riesgo (de todos los análisis)
        cursor.execute('SELECT AVG(risk_score) FROM url_analyses')
        avg_risk_result = cursor.fetchone()
        avg_risk = avg_risk_result[0] if avg_risk_result[0] is not None else 0
        
        print("\n" + "="*60)
        print("ESTADÍSTICAS DE ANÁLISIS - PHISHSHIELD (BD 4NF)")
        print("="*60)
        print(f"🌐 URLs únicas analizadas: {total_unique_urls}")
        print(f"📊 Total de análisis realizados: {total_analyses}")
        print(f"🚨 URLs maliciosas (alguna vez): {ever_malicious_urls}")
        print(f"⚠️  Análisis maliciosos (total): {malicious_analyses}")
        print(f"📈 Puntuación de riesgo promedio: {avg_risk:.2f}/10")
        
        # 6. Distribución de puntuaciones de riesgo (basada en análisis)
        print("\n📋 DISTRIBUCIÓN DE RIESGO (por análisis):")
        cursor.execute('SELECT risk_score FROM url_analyses')
        scores = cursor.fetchall()
        
        risk_distribution = [0, 0, 0, 0]  # bajo, medio-bajo, medio, alto
        for score in scores:
            risk_value = score[0]
            if risk_value <= 2:
                risk_distribution[0] += 1
            elif risk_value <= 4:
                risk_distribution[1] += 1
            elif risk_value <= 7:
                risk_distribution[2] += 1
            else:
                risk_distribution[3] += 1
        
        total_scores = len(scores)
        if total_scores > 0:
            print(f"  🔵 Muy bajo (0-2): {risk_distribution[0]} análisis ({risk_distribution[0]/total_scores*100:.1f}%)")
            print(f"  🟢 Bajo (3-4): {risk_distribution[1]} análisis ({risk_distribution[1]/total_scores*100:.1f}%)")
            print(f"  🟡 Medio (5-7): {risk_distribution[2]} análisis ({risk_distribution[2]/total_scores*100:.1f}%)")
            print(f"  🔴 Alto (8-10): {risk_distribution[3]} análisis ({risk_distribution[3]/total_scores*100:.1f}%)")
        
        # 7. Detecciones por fuente
        print("\n🔍 DETECCIONES POR FUENTE:")
        cursor.execute('''
            SELECT source, COUNT(*) 
            FROM analysis_results 
            WHERE result = 1 
            GROUP BY source
        ''')
        sources = cursor.fetchall()
        
        source_detections = {'VirusTotal': 0, 'Heuristic': 0, 'PhishTank': 0}
        for source in sources:
            source_name = source[0]
            count = source[1]
            source_detections[source_name] = count
            print(f"  {source_name}: {count} detecciones")
        
        # 8. Top dominios con más análisis maliciosos
        print("\n🚨 TOP 10 DOMINIOS CON MÁS ANÁLISIS MALICIOSOS:")
        cursor.execute('''
            SELECT u.domain, COUNT(*) as malicious_count
            FROM urls u
            JOIN url_analyses ua ON u.id = ua.url_id
            WHERE ua.is_malicious = 1
            GROUP BY u.domain
            ORDER BY malicious_count DESC
            LIMIT 10
        ''')
        
        malicious_domains = cursor.fetchall()
        if malicious_domains:
            for i, (domain, count) in enumerate(malicious_domains, 1):
                print(f"  {i}. {domain}: {count} análisis maliciosos")
        else:
            print("  No hay dominios maliciosos registrados")
        
        # 9. URLs con múltiples análisis (historial)
        print("\n📅 URLs CON MÚLTIPLES ANÁLISIS (Top 5):")
        cursor.execute('''
            SELECT u.url, COUNT(ua.id) as analysis_count
            FROM urls u
            JOIN url_analyses ua ON u.id = ua.url_id
            GROUP BY u.id
            HAVING analysis_count > 1
            ORDER BY analysis_count DESC
            LIMIT 5
        ''')
        
        multi_analysis_urls = cursor.fetchall()
        if multi_analysis_urls:
            for url, count in multi_analysis_urls:
                print(f"  {url}: {count} análisis")
        else:
            print("  No hay URLs con análisis múltiples")
        
        # 10. Evolución temporal (últimos 7 días)
        print("\n📊 ACTIVIDAD RECIENTE (Últimos 7 días):")
        cursor.execute('''
            SELECT DATE(analysis_date) as analysis_day, COUNT(*) as daily_analyses
            FROM url_analyses
            WHERE analysis_date >= date('now', '-7 days')
            GROUP BY analysis_day
            ORDER BY analysis_day DESC
        ''')
        
        recent_activity = cursor.fetchall()
        if recent_activity:
            for day, count in recent_activity:
                print(f"  {day}: {count} análisis")
        else:
            print("  No hay actividad en los últimos 7 días")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error generando estadísticas: {e}")
        import traceback
        traceback.print_exc()

def check_database_structure():
    """
    Verifica que la estructura de la BD sea compatible (4NF)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que existen las tablas de la nueva estructura
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            AND name IN ('urls', 'url_analyses', 'analysis_results')
        """)
        tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = {'urls', 'url_analyses', 'analysis_results'}
        missing_tables = required_tables - set(tables)
        
        if missing_tables:
            print(f"❌ ERROR: Faltan tablas en la BD: {missing_tables}")
            print("💡 Ejecuta primero tu app.py para crear la estructura 4NF")
            return False
        
        print("✅ Estructura de BD 4NF verificada correctamente")
        return True
        
    except Exception as e:
        print(f"❌ Error verificando estructura de BD: {e}")
        return False
    finally:
        conn.close()

def main():
    """
    Función principal para cargar y procesar URLs - ACTUALIZADA para 4NF
    """
    print("🔍 PHISHSHIELD - Análisis masivo de URLs")
    print("📊 COMPATIBLE CON BASE DE DATOS 4NF")
    print("="*50)
    
    # Primero verificar la estructura de la BD
    if not check_database_structure():
        return
    
    # Leer URLs desde archivo
    urls = read_urls_from_file(URLS_FILE)
    
    if not urls:
        print(f"❌ No se encontraron URLs en {URLS_FILE}")
        print("💡 Formato esperado:")
        print("  - CSV con columna 'url'")
        print("  - TXT con una URL por línea")
        print("💡 Ejecuta primero el script de scraping para generar URLs")
        return
    
    print(f"📖 Leídas {len(urls)} URLs desde {URLS_FILE}")
    
    # Obtener URLs ya existentes en la BD
    existing_urls = get_existing_urls()
    new_urls = [url for url in urls if url not in existing_urls]
    
    print(f"📊 {len(existing_urls)} URLs ya analizadas previamente")
    print(f"🆕 {len(new_urls)} nuevas URLs para analizar")
    
    # Mostrar información sobre la nueva estructura 4NF
    print("\n💡 INFORMACIÓN BD 4NF:")
    print("  - Cada URL puede tener múltiples análisis en el tiempo")
    print("  - Se guarda historial completo de cada análisis")
    print("  - Estadísticas más precisas y detalladas")
    
    # Preguntar si procesar solo las nuevas o todas
    if len(existing_urls) > 0:
        choice = input("\n¿Procesar solo las nuevas URLs? (s/n): ").lower().strip()
        if choice != 's':
            new_urls = urls  # Procesar todas
            print("🔁 Procesando TODAS las URLs (incluyendo existentes)")
        else:
            print("🔍 Procesando solo URLs NUEVAS")
    else:
        print("🎯 Procesando todas las URLs (primera ejecución)")
    
    if not new_urls:
        print("✅ No hay URLs nuevas para analizar")
        export_statistics()
        return
    
    # Confirmar antes de proceder
    estimated_minutes = len(new_urls) * DELAY_BETWEEN_REQUESTS / 60
    print(f"⏰ Tiempo estimado: {estimated_minutes:.1f} minutos")
    print(f"📦 URLs a procesar: {len(new_urls)}")
    
    confirm = input("\n¿Iniciar análisis masivo? (s/n): ").lower().strip()
    if confirm != 's':
        print("❌ Análisis cancelado por el usuario")
        return
    
    # Procesar URLs en lotes
    start_time = time.time()
    successful = 0
    
    # Dividir en lotes para mejor manejo
    batch_size = 10
    batches = [new_urls[i:i + batch_size] for i in range(0, len(new_urls), batch_size)]
    
    print(f"\n🔄 Iniciando análisis de {len(new_urls)} URLs en {len(batches)} lotes...")
    
    for i, batch in enumerate(batches):
        print(f"\n📦 Lote {i+1}/{len(batches)} ({len(batch)} URLs)")
        successful_in_batch = process_urls_batch(batch)
        successful += successful_in_batch
        
        # Mostrar progreso detallado
        progress = (i + 1) / len(batches) * 100
        elapsed_time = time.time() - start_time
        estimated_total = elapsed_time / progress * 100 if progress > 0 else 0
        remaining = estimated_total - elapsed_time
        
        print(f"📊 Progreso: {successful}/{len(new_urls)} completadas ({progress:.1f}%)")
        print(f"⏱️  Tiempo transcurrido: {elapsed_time/60:.1f}min - Restante: {remaining/60:.1f}min")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Resultados finales
    print(f"\n{'='*60}")
    print("🎉 ANÁLISIS MASIVO COMPLETADO")
    print(f"{'='*60}")
    print(f"✅ URLs procesadas con éxito: {successful}/{len(new_urls)}")
    print(f"⏰ Tiempo total: {total_time/60:.1f} minutos")
    print(f"📈 Tasa de éxito: {successful/len(new_urls)*100:.1f}%")
    

if __name__ == "__main__":
    main()