import sys
import os
import re
import requests
import json
from typing import List, Dict, Tuple
from urllib.parse import urlparse

def resource_path(relative_path):
    """Поддержка пути внутри .app и при запуске напрямую"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


class URLChecker:
    def __init__(self, config_file=None):
        if config_file is None:
            config_file = resource_path('checker_config.json')

        self.config = self._load_config(config_file)
        self.endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.phishing_rules = self.config.get('phishingRules', {})
        self.trusted_domains = {
            'habr.com', 'github.com', 'stackoverflow.com', 'python.org',
            'mail.ru', 'yandex.ru', 'google.com', 'microsoft.com', 'apple.com', 'wikipedia.org'
        }

        # log_file = resource_path('url_checker.log')  # если понадобится логгер


        log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'url_checker.log')
        # self.logger = logging.getLogger('url_checker')
        # self.logger.setLevel(logging.INFO)
        # handler = logging.FileHandler(log_file)
        # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # handler.setFormatter(formatter)
        # self.logger.addHandler(handle%r)

    def _load_config(self, config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as file:
                return json.load(file)
        except FileNotFoundError:
            # self.logger.error(f"Файл конфигурации '{config_file}' не найден.")
            raise
        except json.JSONDecodeError:
            # self.logger.error(f"Ошибка при чтении JSON-файла '{config_file}'.")
            raise

    def is_trusted_domain(self, url: str) -> bool:
        try:
            domain = urlparse(url).netloc
            domain = domain.replace('www.', '')
            return any(domain.endswith(trusted) for trusted in self.trusted_domains)
        except Exception:
            # self.logger.error(f"Ошибка при проверке домена {url}: {e}")
            return False

    def check_phishing_patterns(self, text: str) -> Tuple[bool, List[str]]:
        text = text.lower()
        reasons = []
        for keyword in self.phishing_rules.get('keywords', []):
            if keyword.lower() in text:
                reasons.append(f"Обнаружено подозрительное ключевое слово: {keyword}")
        for urgency in self.phishing_rules.get('suspiciousPatterns', {}).get('urgency', []):
            if urgency.lower() in text:
                reasons.append(f"Обнаружен признак срочности: {urgency}")
        for pressure in self.phishing_rules.get('suspiciousPatterns', {}).get('pressure', []):
            if pressure.lower() in text:
                reasons.append(f"Обнаружен признак давления: {pressure}")
        for sensitive in self.phishing_rules.get('suspiciousPatterns', {}).get('sensitive', []):
            if sensitive.lower() in text:
                reasons.append(f"Запрос конфиденциальных данных: {sensitive}")
        is_phishing = len(reasons) >= 2
        return is_phishing, reasons

    def extract_links(self, text):
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        links = re.findall(url_pattern, text)
        # self.logger.info(f"Найденные ссылки: {links}")
        return links

    def check_url_safety(self, url, api_key=None):
        if self.is_trusted_domain(url):
            # self.logger.info(f"✅ Ссылка '{url}' принадлежит доверенному домену.")
            return True
        for pattern in self.phishing_rules.get('urlPatterns', []):
            if pattern.lower() in url.lower():
                # self.logger.warning(f"⚠️ Подозрительный паттерн '{pattern}' в ссылке '{url}'")
                return False
        if api_key:
            try:
                payload = {
                    "client": {
                        "clientId": self.config.get('clientId', "email-spam-detector"),
                        "clientVersion": self.config.get('clientVersion', "1.0.0")
                    },
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                response = requests.post(self.endpoint, params={'key': api_key}, json=payload)
                if response.status_code == 200 and response.json().get('matches'):
                    # self.logger.warning(f"⚠️ Google Safe Browsing пометил ссылку '{url}' как опасную")
                    return False
            except Exception:
                # self.logger.error(f"Ошибка при проверке URL через Google API: {e}")
                pass
        return True

    def analyze_email(self, subject: str, body: str, api_key: str) -> Dict:
        result = {
            "is_phishing": False,
            "is_safe": True,
            "threats": [],
            "suspicious_links": [],
            "phishing_indicators": []
        }
        subject_phishing, subject_reasons = self.check_phishing_patterns(subject)
        body_phishing, body_reasons = self.check_phishing_patterns(body)
        if subject_phishing or body_phishing:
            result["is_phishing"] = True
            result["phishing_indicators"].extend(subject_reasons + body_reasons)
        links = self.extract_links(body)
        suspicious_count = 0
        for link in links:
            if not self.check_url_safety(link, api_key):
                suspicious_count += 1
                result["suspicious_links"].append(link)
        if suspicious_count >= 2:
            result["is_safe"] = False
        if result["is_phishing"]:
            result["threats"].append("Обнаружены признаки фишинга")
        if not result["is_safe"]:
            result["threats"].append("Обнаружены подозрительные ссылки")
        return result
