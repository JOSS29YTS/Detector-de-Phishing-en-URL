import os
import sys
import time
import subprocess
import socket
from playwright.sync_api import sync_playwright

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def wait_for_server(url, timeout=15):
    import urllib.request
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = urllib.request.urlopen(url, timeout=1)
            if response.status == 200:
                print("[INFO] Servidor Flask detectado y respondiendo!")
                return True
        except Exception:
            pass
        time.sleep(0.5)
    print("[ERROR] Tiempo de espera agotado para el servidor Flask.")
    return False

def main():
    # 1. Definir rutas y directorios
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, "screenshots-phishing")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[INFO] Creada carpeta de capturas: {output_dir}")
    else:
        print(f"[INFO] La carpeta de capturas ya existe: {output_dir}")

    # 2. Iniciar servidor Flask
    port = 5000
    if is_port_in_use(port):
        print(f"[WARNING] El puerto {port} ya está en uso. Intentaremos usar la instancia en ejecución.")
        flask_process = None
    else:
        print("[INFO] Iniciando servidor Flask...")
        flask_dir = os.path.join(base_dir, "URL")
        
        # Seteamos PYTHONIOENCODING en utf-8 para que app.py no falle al imprimir emojis en consola de Windows
        custom_env = {
            **os.environ,
            "FLASK_ENV": "development",
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8"
        }
        
        flask_process = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=flask_dir,
            env=custom_env
        )
        # Esperar a que el servidor esté activo
        if not wait_for_server(f"http://127.0.0.1:{port}/"):
            if flask_process:
                flask_process.terminate()
            sys.exit(1)

    # 3. Inicializar Playwright
    print("[INFO] Iniciando Playwright y Chromium...")
    with sync_playwright() as p:
        # Lanzamos Chromium en modo headless con un tamaño de ventana premium
        browser = p.chromium.launch(headless=True)
        # Usamos un dispositivo de escritorio premium (1280x880)
        context = browser.new_context(
            viewport={"width": 1280, "height": 880},
            device_scale_factor=1.25 # Mayor densidad de pixeles para capturas nítidas
        )
        page = context.new_page()

        try:
            # --- 01. INICIO VACÍO ---
            print("[INFO] Capturando Inicio Vacio...")
            page.goto(f"http://127.0.0.1:{port}/")
            # Esperar a que cargue la página y se renderice AOS / Feather
            page.wait_for_timeout(2000)
            page.screenshot(path=os.path.join(output_dir, "01_home_empty.png"))

            # --- 02. ANÁLISIS URL SEGURA (GOOGLE) ---
            print("[INFO] Analizando URL segura y capturando resultado...")
            page.fill("#url-input", "https://www.google.com")
            # Hacer clic en el botón de Analizar
            page.click("#url-form button[type='submit']")
            
            # Esperar a que aparezca la sección de resultados
            page.wait_for_selector("#results-section:not(.result-section)", timeout=15000)
            page.wait_for_timeout(2000)
            # Scroll sutil para centrar los resultados
            page.evaluate("window.scrollTo({ top: 300, behavior: 'smooth' })")
            page.wait_for_timeout(1000)
            page.screenshot(path=os.path.join(output_dir, "02_home_analyzed_secure.png"))

            # --- 03. ANÁLISIS URL PHISHING (SIMULADA) ---
            print("[INFO] Analizando URL phishing simulada y capturando resultado...")
            # Limpiar
            page.click("#clear-btn")
            page.wait_for_timeout(500)
            # Escribir URL que dispare el análisis heurístico con alta puntuación
            phishing_url = "http://signin-paypal-verify-account-update-confirm.info"
            page.fill("#url-input", phishing_url)
            page.click("#url-form button[type='submit']")
            
            # Esperar resultados
            page.wait_for_selector("#results-section:not(.result-section)", timeout=15000)
            page.wait_for_timeout(2000)
            # Scroll sutil para centrar la recomendación de peligro (roja)
            page.evaluate("window.scrollTo({ top: 350, behavior: 'smooth' })")
            page.wait_for_timeout(1000)
            page.screenshot(path=os.path.join(output_dir, "03_home_analyzed_phishing.png"))

            # --- 04. ESTADÍSTICAS ---
            print("[INFO] Capturando Estadisticas...")
            page.goto(f"http://127.0.0.1:{port}/stats")
            # Esperar a que el JS cargue los datos de la base de datos y carguen los gráficos
            page.wait_for_timeout(3000)
            page.screenshot(path=os.path.join(output_dir, "04_stats.png"))

            # --- 05. DOCUMENTACIÓN ---
            print("[INFO] Capturando Documentacion...")
            page.goto(f"http://127.0.0.1:{port}/docs")
            page.wait_for_timeout(1500)
            page.screenshot(path=os.path.join(output_dir, "05_docs.png"))

            # --- 06. API REST ---
            print("[INFO] Capturando API REST...")
            page.goto(f"http://127.0.0.1:{port}/api-rest")
            page.wait_for_timeout(1500)
            page.screenshot(path=os.path.join(output_dir, "06_api_rest.png"))

            # --- 07. BLOG ---
            print("[INFO] Capturando Blog...")
            page.goto(f"http://127.0.0.1:{port}/blog")
            page.wait_for_timeout(1500)
            page.screenshot(path=os.path.join(output_dir, "07_blog.png"))

            # --- 08. TÉRMINOS ---
            print("[INFO] Capturando Terminos...")
            page.goto(f"http://127.0.0.1:{port}/terms")
            page.wait_for_timeout(1500)
            page.screenshot(path=os.path.join(output_dir, "08_terms.png"))

            # --- 09. PRIVACIDAD ---
            print("[INFO] Capturando Privacidad...")
            page.goto(f"http://127.0.0.1:{port}/privacy")
            page.wait_for_timeout(1500)
            page.screenshot(path=os.path.join(output_dir, "09_privacy.png"))

            # --- 10. SEGURIDAD ---
            print("[INFO] Capturando Seguridad...")
            page.goto(f"http://127.0.0.1:{port}/security")
            page.wait_for_timeout(1500)
            page.screenshot(path=os.path.join(output_dir, "10_security.png"))

            # --- 11. GDPR ---
            print("[INFO] Capturando GDPR...")
            page.goto(f"http://127.0.0.1:{port}/gdpr")
            page.wait_for_timeout(1500)
            page.screenshot(path=os.path.join(output_dir, "11_gdpr.png"))

            print("[SUCCESS] Todas las capturas de pantalla se generaron con exito!")

        except Exception as e:
            print(f"[ERROR] Ocurrio un error durante la automatizacion: {e}")
        finally:
            browser.close()

    # 4. Detener servidor Flask si lo iniciamos nosotros
    if flask_process:
        print("[INFO] Cerrando servidor Flask de prueba...")
        flask_process.terminate()
        flask_process.wait()
        print("[INFO] Servidor Flask apagado.")

if __name__ == "__main__":
    main()
