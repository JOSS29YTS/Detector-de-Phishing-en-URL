import requests
from bs4 import BeautifulSoup
import csv
import random
import time
from urllib.parse import urljoin, urlparse
import logging
import concurrent.futures
from collections import Counter
import json

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AdvancedURLScraper:
    def __init__(self):
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
        self.visited_urls = set()
        self.all_urls = set()
        
    def get_random_headers(self):
        """Genera headers aleatorios para evitar bloqueos"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def is_valid_url(self, url):
        """Verifica si una URL es válida y segura"""
        try:
            parsed = urlparse(url)
            if not bool(parsed.netloc and parsed.scheme in ['http', 'https']):
                return False
            
            # Excluir tipos de archivos no deseados
            excluded_extensions = ['.pdf', '.doc', '.docx', '.zip', '.exe', '.jpg', '.png', '.gif']
            if any(url.lower().endswith(ext) for ext in excluded_extensions):
                return False
                
            # Excluir URLs con parámetros sospechosos
            suspicious_keywords = ['login', 'signin', 'admin', 'dashboard', 'password']
            if any(keyword in url.lower() for keyword in suspicious_keywords):
                return False
                
            return True
        except:
            return False

    def get_extended_site_list(self):
        """Lista extendida de sitios para scraping - MÁS DE 200 SITIOS"""
        return [
            # Noticias y Medios (50 sitios)
            "https://www.bbc.com/news", "https://edition.cnn.com", "https://www.reuters.com",
            "https://www.theguardian.com/international", "https://www.nytimes.com",
            "https://www.washingtonpost.com", "https://www.nbcnews.com", "https://www.cbsnews.com",
            "https://abcnews.go.com", "https://www.foxnews.com", "https://www.huffpost.com",
            "https://www.usatoday.com", "https://www.latimes.com", "https://www.chicagotribune.com",
            "https://www.newsweek.com", "https://time.com", "https://www.bloomberg.com",
            "https://www.forbes.com", "https://fortune.com", "https://www.businessinsider.com",
            "https://www.wired.com", "https://techcrunch.com", "https://mashable.com",
            "https://gizmodo.com", "https://www.theverge.com", "https://www.engadget.com",
            "https://www.cnet.com", "https://arstechnica.com", "https://www.scientificamerican.com",
            "https://www.nature.com", "https://www.science.org", "https://www.nationalgeographic.com",
            "https://www.history.com", "https://www.smithsonianmag.com", "https://www.espn.com",
            "https://www.si.com", "https://www.eurosport.com", "https://www.weather.com",
            "https://www.aljazeera.com", "https://www.france24.com", "https://www.dw.com",
            "https://www.rt.com", "https://www.scmp.com", "https://www.asahi.com",
            "https://www.thejakartapost.com", "https://www.straitstimes.com", "https://www.thehindu.com",
            
            # Tecnología y Programación (40 sitios)
            "https://stackoverflow.com", "https://github.com", "https://gitlab.com",
            "https://bitbucket.org", "https://www.reddit.com/r/programming", "https://www.reddit.com/r/technology",
            "https://news.ycombinator.com", "https://lobste.rs", "https://dev.to",
            "https://medium.com/tag/technology", "https://medium.com/tag/programming",
            "https://css-tricks.com", "https://www.smashingmagazine.com", "https://alistapart.com",
            "https://www.codeproject.com", "https://dzone.com", "https://infoq.com",
            "https://www.theregister.com", "https://www.zdnet.com", "https://www.computerworld.com",
            "https://www.pcmag.com", "https://www.howtogeek.com", "https://www.lifewire.com",
            "https://www.digitaltrends.com", "https://www.techradar.com", "https://www.androidauthority.com",
            "https://www.xda-developers.com", "https://www.iphonehacks.com", "https://www.macrumors.com",
            "https://www.anandtech.com", "https://www.tomshardware.com", "https://www.guru3d.com",
            "https://www.phoronix.com", "https://www.slashdot.org", "https://www.omgubuntu.co.uk",
            "https://www.linux.com", "https://www.ubuntu.com", "https://www.apache.org",
            "https://www.python.org", "https://www.java.com",
            
            # Educación y Referencia (30 sitios)
            "https://www.wikipedia.org", "https://www.britannica.com", "https://www.khanacademy.org",
            "https://www.coursera.org", "https://www.edx.org", "https://www.udemy.com",
            "https://www.academicearth.org", "https://www.ted.com", "https://www.quizlet.com",
            "https://www.wolframalpha.com", "https://www.stackexchange.com", "https://www.quora.com",
            "https://www.answers.com", "https://www.ehow.com", "https://www.wikihow.com",
            "https://www.instructables.com", "https://www.citationmachine.net", "https://www.grammarly.com",
            "https://www.dictionary.com", "https://www.thesaurus.com", "https://www.merriam-webster.com",
            "https://www.oxfordlearnersdictionaries.com", "https://www.cambridge.org",
            "https://www.harvard.edu", "https://www.stanford.edu", "https://www.mit.edu",
            "https://www.princeton.edu", "https://www.yale.edu", "https://www.columbia.edu",
            
            # Comercio Electrónico y Negocios (40 sitios)
            "https://www.amazon.com", "https://www.ebay.com", "https://www.walmart.com",
            "https://www.target.com", "https://www.bestbuy.com", "https://www.apple.com",
            "https://www.microsoft.com", "https://www.dell.com", "https://www.hp.com",
            "https://www.lenovo.com", "https://www.samsung.com", "https://www.sony.com",
            "https://www.lg.com", "https://www.ikea.com", "https://www.homedepot.com",
            "https://www.lowes.com", "https://www.sears.com", "https://www.macys.com",
            "https://www.nordstrom.com", "https://www.gap.com", "https://www.zara.com",
            "https://www.hm.com", "https://www.uniqlo.com", "https://www.nike.com",
            "https://www.adidas.com", "https://www.underarmour.com", "https://www.etsy.com",
            "https://www.wayfair.com", "https://www.overstock.com", "https://www.newegg.com",
            "https://www.tigerdirect.com", "https://www.costco.com", "https://www.samsclub.com",
            "https://www.officedepot.com", "https://www.staples.com", "https://www.bestbuy.com",
            "https://www.bhphotovideo.com", "https://www.crutchfield.com", "https://www.threadless.com",
            
            # Viajes y Turismo (25 sitios)
            "https://www.tripadvisor.com", "https://www.booking.com", "https://www.expedia.com",
            "https://www.kayak.com", "https://www.skyscanner.com", "https://www.airbnb.com",
            "https://www.hostelworld.com", "https://www.lonelyplanet.com", "https://www.roughguides.com",
            "https://www.fodors.com", "https://www.frommers.com", "https://www.ricksteves.com",
            "https://www.nationalgeographic.com/travel", "https://www.cntraveler.com",
            "https://www.travelandleisure.com", "https://www.afar.com", "https://www.matadornetwork.com",
            "https://www.theplanetd.com", "https://www.neverendingvoyage.com",
            "https://www.legalnomads.com", "https://www.ytravelblog.com", "https://www.uncorneredmarket.com",
            "https://www.ourdreamtravel.com", "https://www.worldofwanderlust.com",
            
            # Entretenimiento y Cultura (30 sitios)
            "https://www.imdb.com", "https://www.rottentomatoes.com", "https://www.metacritic.com",
            "https://www.netflix.com", "https://www.hulu.com", "https://www.disneyplus.com",
            "https://www.hbomax.com", "https://www.primevideo.com", "https://www.spotify.com",
            "https://www.youtube.com", "https://www.vimeo.com", "https://www.dailymotion.com",
            "https://www.twitch.tv", "https://www.goodreads.com", "https://www.librarything.com",
            "https://www.anilist.co", "https://www.myanimelist.net", "https://www.pinterest.com",
            "https://www.deviantart.com", "https://www.behance.net", "https://www.dribbble.com",
            "https://www.artstation.com", "https://www.500px.com", "https://www.flickr.com",
            "https://www.instagram.com", "https://www.tiktok.com", "https://www.twitter.com",
            "https://www.facebook.com", "https://www.linkedin.com", "https://www.reddit.com"
        ]

    def extract_urls_from_site(self, url, max_urls=100):
        """Extrae URLs de un sitio web específico de forma más exhaustiva"""
        try:
            headers = self.get_random_headers()
            response = self.session.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            extracted_urls = set()
            
            # Extraer enlaces de diferentes elementos HTML
            for element in soup.find_all(['a', 'link', 'area', 'iframe']):
                href = element.get('href') or element.get('src')
                if href:
                    full_url = urljoin(url, href)
                    if self.is_valid_url(full_url) and full_url not in self.visited_urls:
                        extracted_urls.add(full_url)
                        self.visited_urls.add(full_url)
                        
                        if len(extracted_urls) >= max_urls:
                            break
            
            # También buscar en meta tags y scripts
            for meta in soup.find_all('meta', content=True):
                content = meta.get('content', '')
                if content.startswith(('http://', 'https://')):
                    if self.is_valid_url(content) and content not in self.visited_urls:
                        extracted_urls.add(content)
                        self.visited_urls.add(content)
            
            logging.info(f"✅ Extraídas {len(extracted_urls)} URLs de {urlparse(url).netloc}")
            return extracted_urls
            
        except Exception as e:
            logging.error(f"❌ Error extrayendo de {url}: {str(e)}")
            return set()

    def scrape_site_parallel(self, site_url):
        """Scraping de un sitio en paralelo"""
        try:
            urls = self.extract_urls_from_site(site_url, max_urls=80)
            time.sleep(random.uniform(1, 2))  # Pausa más corta para paralelismo
            return urls
        except Exception as e:
            logging.error(f"Error en scraping paralelo de {site_url}: {e}")
            return set()

    def get_massive_urls(self, target_count=10000, max_workers=10):
        """Obtiene URLs masivas usando paralelismo"""
        all_urls = set()
        sites = self.get_extended_site_list()
        
        print(f"🎯 Objetivo: {target_count} URLs")
        print(f"🔧 Usando {max_workers} workers paralelos")
        print("🔄 Iniciando scraping masivo...")
        
        # Scraping paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_site = {executor.submit(self.scrape_site_parallel, site): site for site in sites}
            
            for i, future in enumerate(concurrent.futures.as_completed(future_to_site)):
                site = future_to_site[future]
                try:
                    urls = future.result()
                    all_urls.update(urls)
                    
                    # Progreso en tiempo real
                    progress = (i + 1) / len(sites) * 100
                    print(f"📊 Progreso: {i+1}/{len(sites)} sitios ({progress:.1f}%) - URLs recolectadas: {len(all_urls)}")
                    
                    if len(all_urls) >= target_count:
                        print("🎯 Objetivo alcanzado, terminando scraping...")
                        break
                        
                except Exception as e:
                    logging.error(f"Error procesando {site}: {e}")
        
        # Si no alcanzamos el objetivo, agregar más URLs de fuentes adicionales
        if len(all_urls) < target_count:
            print(f"🔄 Recolectando URLs adicionales...")
            additional_sources = [
                "https://www.dmoz-odp.org", "https://www.alexa.com/topsites",
                "https://start.me/start", "https://www.allmyfaves.com",
                "https://www.similarsites.com", "https://www.webfeeds.com"
            ]
            
            for source in additional_sources:
                if len(all_urls) >= target_count:
                    break
                urls = self.extract_urls_from_site(source, max_urls=200)
                all_urls.update(urls)
                print(f"➕ {len(urls)} URLs de {source} - Total: {len(all_urls)}")
                time.sleep(2)
        
        return list(all_urls)[:target_count]

    def save_to_csv(self, urls, filename='urls_to_analyze.csv'):
        """Guarda las URLs en un archivo CSV"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['url'])
                
                for url in urls:
                    writer.writerow([url])
            
            logging.info(f"💾 Guardadas {len(urls)} URLs en {filename}")
            return True
            
        except Exception as e:
            logging.error(f"❌ Error guardando CSV: {str(e)}")
            return False

    def analyze_url_distribution(self, urls):
        """Analiza la distribución de dominios en las URLs"""
        domains = [urlparse(url).netloc for url in urls]
        domain_counts = Counter(domains)
        
        print("\n" + "="*70)
        print("📊 ANÁLISIS COMPLETO DE URLs RECOLECTADAS")
        print("="*70)
        print(f"🌐 URLs totales recolectadas: {len(urls):,}")
        print(f"🏷️  Dominios únicos: {len(domain_counts):,}")
        
        print("\n🏆 TOP 15 DOMINIOS MÁS FRECUENTES:")
        for domain, count in domain_counts.most_common(15):
            percentage = (count / len(urls)) * 100
            print(f"  {domain}: {count:,} URLs ({percentage:.1f}%)")
        
        # Análisis de TLDs (Top Level Domains)
        tlds = [urlparse(url).netloc.split('.')[-1] for url in urls]
        tld_counts = Counter(tlds)
        
        print(f"\n🌍 DISTRIBUCIÓN POR TLD (Top 10):")
        for tld, count in tld_counts.most_common(10):
            percentage = (count / len(urls)) * 100
            print(f"  .{tld}: {count:,} URLs ({percentage:.1f}%)")
        
        # URLs por categoría aproximada
        categories = {
            'Noticias': sum(1 for url in urls if any(keyword in url for keyword in ['news', 'reuters', 'cnn', 'bbc'])),
            'Tecnología': sum(1 for url in urls if any(keyword in url for keyword in ['tech', 'github', 'stack', 'programming'])),
            'Comercio': sum(1 for url in urls if any(keyword in url for keyword in ['shop', 'store', 'amazon', 'ebay'])),
            'Educación': sum(1 for url in urls if any(keyword in url for keyword in ['edu', 'academy', 'learn', 'course'])),
            'Entretenimiento': sum(1 for url in urls if any(keyword in url for keyword in ['video', 'movie', 'music', 'game']))
        }
        
        print(f"\n📂 DISTRIBUCIÓN POR CATEGORÍA APROXIMADA:")
        for category, count in categories.items():
            percentage = (count / len(urls)) * 100
            print(f"  {category}: {count:,} URLs ({percentage:.1f}%)")

def main():
    """Función principal mejorada"""
    print("🚀 SCRAPER AVANZADO DE URLs MASIVAS")
    print("✨ Generando dataset masivo para análisis de phishing")
    print("="*70)
    
    scraper = AdvancedURLScraper()
    
    # Configuración
    target_urls = 15000  # Objetivo ambicioso
    max_workers = 8      # Número de hilos paralelos
    
    start_time = time.time()
    
    # Obtener URLs masivas
    urls = scraper.get_massive_urls(target_urls, max_workers)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    if urls:
        # Guardar en CSV
        output_file = 'urls_to_analyze.csv'
        scraper.save_to_csv(urls, output_file)
        
        # Mostrar análisis completo
        scraper.analyze_url_distribution(urls)
        
        # Estadísticas de rendimiento
        print(f"\n⏱️  ESTADÍSTICAS DE RENDIMIENTO:")
        print(f"  Tiempo total: {total_time/60:.1f} minutos")
        print(f"  URLs por minuto: {len(urls)/(total_time/60):.0f}")
        print(f"  Tasa de éxito: {(len(urls)/target_urls)*100:.1f}%")
        
        # Mostrar ejemplos representativos
        print(f"\n🔍 EJEMPLOS REPRESENTATIVOS:")
        sample_size = min(15, len(urls))
        sample_urls = random.sample(urls, sample_size)
        
        for i, url in enumerate(sample_urls, 1):
            domain = urlparse(url).netloc
            print(f"  {i:2d}. {domain} → {url[:80]}{'...' if len(url) > 80 else ''}")
        
        print(f"\n✅ ¡SCRAPING COMPLETADO!")
        print(f"💾 Archivo guardado: {output_file}")
        print(f"🎯 Ejecuta: python bulk_analyzer.py")
        
    else:
        print("❌ No se pudieron obtener URLs suficientes")

if __name__ == "__main__":
    main()