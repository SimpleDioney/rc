import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os
import requests
from urllib.parse import urljoin

class MangaScraper:
    def __init__(self, download_folder):
        self.download_folder = download_folder
        self.driver = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Referer': 'https://tsuki-mangas.com/'
        })

    def setup(self):
        try:
            options = uc.ChromeOptions()
            options.headless = False
            self.driver = uc.Chrome(options=options)
        except Exception as e:
            print(f"Error during setup: {str(e)}")
            if self.driver:
                self.driver.quit()
            raise

    def download_image(self, url, filename, retries=3):
        for attempt in range(retries):
            try:
                response = self.session.get(url)
                if response.status_code == 200:
                    data = response.content
                    if len(data) < 1024:  # Check if image is too small
                        raise ValueError("Image too small - possible error")
                    
                    with open(filename, 'wb') as f:
                        f.write(data)
                    print(f"Downloaded: {filename}")
                    return True
                elif response.status_code == 404:
                    print(f"Image not found (404): {url}")
                    return False
            except Exception as e:
                print(f"Attempt {attempt + 1}/{retries} failed for {url}: {str(e)}")
                if attempt == retries - 1:
                    print(f"Failed to download {url} after {retries} attempts")
                    return False
                time.sleep(2)
        return False

    def get_base_url(self):
        try:
            # Locate the image element by its class name
            img_element = self.driver.find_element(By.CLASS_NAME, 'pagereader')
            
            # Get the src attribute from the img tag
            img_url = img_element.get_attribute('src')
            
            # The base URL would be everything before the page-specific part (e.g., before '_02.jpg')
            base_url = img_url.rsplit('_', 1)[0]
            
            return base_url
        except Exception as e:
            print(f"Error retrieving base URL: {str(e)}")
            return None
            
        except Exception as e:
            print(f"Erro ao obter URL base: {str(e)}")
            return None

    def scrape(self, url):
        try:
            print(f"Iniciando download do capítulo: {url}")
            
            os.makedirs(self.download_folder, exist_ok=True)
            
            print("Carregando página...")
            self.driver.get(url)
            time.sleep(5)  # Espera a página carregar
            
            print("Obtendo URL base...")
            base_url = self.get_base_url()
            
            if not base_url:
                raise Exception("Não foi possível obter o URL base das imagens")
            
            print(f"URL base encontrada: {base_url}")
            
            # Tenta baixar imagens sequencialmente
            page_number = 1
            consecutive_failures = 0
            max_consecutive_failures = 3  # Número máximo de falhas consecutivas antes de parar
            
            while consecutive_failures < max_consecutive_failures:
                # Formata o número da página com zeros à esquerda (01, 02, etc)
                page_str = f"_{page_number:02d}.jpg"
                img_url = base_url + page_str
                
                filename = os.path.join(self.download_folder, f"page_{page_number:03d}.jpg")
                
                if self.download_image(img_url, filename):
                    consecutive_failures = 0  # Reseta o contador de falhas
                    page_number += 1
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= max_consecutive_failures:
                        print(f"Atingido número máximo de falhas consecutivas após a página {page_number-1}")
                        break
                
                time.sleep(1)  # Pequena pausa entre downloads
            
            print(f"Download concluído. Total de páginas: {page_number-1}")
            
        except Exception as e:
            print(f"Erro durante o processo: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            if self.driver:
                self.driver.quit()

def main():
    url = 'https://tsuki-mangas.com/leitor/60/2829/the-beginning-after-the-end/72'
    download_folder = 'C:/Users/dione/Desktop/MANGAS'
    
    scraper = MangaScraper(download_folder)
    scraper.setup()
    scraper.scrape(url)

if __name__ == "__main__":
    main()