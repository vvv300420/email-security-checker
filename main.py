import tkinter as tk
from tkinter import ttk
import json
import ssl
import smtplib
import imaplib
from email.mime.text import MIMEText
from email.parser import BytesParser
from email.policy import default
import re
from utils import URLChecker
import pickle
import sys
import os

def resource_path(relative_path):
    """Получить путь к файлу внутри .app или из текущей папки"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


class EmailSpamChecker:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.google_api_key = None
        self.imap_server = 'imap.mail.ru'
        self.smtp_server = 'smtp.mail.ru'
        self.smtp_port = 465
        self.imap_port = 993

        with open(resource_path('checker_config.json'), 'r', encoding='utf-8') as f:
            self.spam_config = json.load(f)

        self.url_checker = URLChecker()

        try:
            with open(resource_path('spam_model.pkl'), 'rb') as f:
                self.model = pickle.load(f)

        except Exception:
            self.model = None

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def connect(self, log_func=None):
        try:
            if log_func: log_func("Подключение к IMAP...")
            self.imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            self.imap.login(self.email, self.password)
            if log_func: log_func("✅ IMAP подключен")

            if log_func: log_func("Подключение к SMTP...")
            self.smtp = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=self.ssl_context)
            self.smtp.login(self.email, self.password)
            if log_func: log_func("✅ SMTP подключен")
            return True
        except Exception as e:
            if log_func: log_func(f"❌ Ошибка подключения: {e}")
            return False

    def check_spam_patterns(self, subject, body):
        text = f"{subject}\n{body}".lower()
        indicators = []

        for kw in self.spam_config['phishingRules']['keywords']:
            if kw.lower() in text:
                indicators.append(f"Ключевое слово: {kw}")

        for cat, patterns in self.spam_config['phishingRules']['suspiciousPatterns'].items():
            for pattern in patterns:
                if pattern.lower() in text:
                    indicators.append(f"Паттерн ({cat}): {pattern}")

        urls = re.findall(r'https?://[^\s<>"]+', text)
        for url in urls:
            if any(p in url for p in self.spam_config['phishingRules']['urlPatterns']):
                indicators.append(f"Подозрительный URL: {url}")
            if not self.url_checker.check_url_safety(url, self.google_api_key):
                indicators.append(f"⚠️ URL небезопасен: {url}")

        return len(indicators) >= 2, "\n".join(indicators)

    def is_spam_by_model(self, text):
        if self.model:
            return self.model.predict([text])[0] == 1
        return False

    def send_notification(self, subject, text):
        msg = MIMEText(text)
        msg['Subject'] = subject
        msg['From'] = self.email
        msg['To'] = self.email
        self.smtp.send_message(msg)


class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Проверка почты на спам")
        self.root.geometry("500x400")

        main = ttk.Frame(self.root, padding="20")
        main.pack(fill=tk.BOTH, expand=True)

        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.api_key_var = tk.StringVar()

        for label, var, show in [("Email:", self.email_var, ""),
                                 ("Пароль:", self.password_var, "*"),
                                 ("API ключ:", self.api_key_var, "")]:
            ttk.Label(main, text=label).pack(fill=tk.X)
            ttk.Entry(main, textvariable=var, show=show).pack(fill=tk.X)

        ttk.Button(main, text="Проверить почту", command=self.start_checker).pack(pady=10)

        self.output = tk.Text(main, height=12, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True)

        scroll = ttk.Scrollbar(main, orient="vertical", command=self.output.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.output.configure(yscrollcommand=scroll.set)

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.root.update()

    def start_checker(self):
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        api_key = self.api_key_var.get().strip()

        if not email or not password or not api_key:
            self.log("❌ Заполните все поля")
            return

        self.output.delete(1.0, tk.END)
        self.log("🔍 Начинаем проверку...")

        checker = EmailSpamChecker(email, password)
        checker.google_api_key = api_key

        if not checker.connect(log_func=self.log):
            return

        checker.imap.select("INBOX")
        _, messages = checker.imap.search(None, "UNSEEN")
        mail_ids = messages[0].split()

        if not mail_ids:
            self.log("✨ Новых писем нет")
            checker.imap.logout()
            checker.smtp.quit()
            return

        self.log(f"📨 Найдено {len(mail_ids)} писем")
        spam_count = 0

        for i, num in enumerate(mail_ids, 1):
            try:
                _, data = checker.imap.fetch(num, "(RFC822)")
                parser = BytesParser(policy=default)
                msg = parser.parsebytes(data[0][1])
                subject = msg.get("Subject", "(без темы)")
                self.log(f"\n📩 Письмо {i}: {subject}")
                body = ""

                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                else:
                    body = msg.get_payload(decode=True).decode(errors="ignore")

                is_spam, reason = checker.check_spam_patterns(subject, body)

                if checker.is_spam_by_model(body):
                    is_spam = True
                    reason += "\n🤖 Модель также считает это письмо спамом"

                if is_spam:
                    spam_count += 1
                    self.log(f"❌ Спам! Причина:\n{reason}")
                    checker.imap.copy(num, "Spam")
                    checker.imap.store(num, "+FLAGS", "\\Deleted")
                    checker.imap.expunge()
                    checker.send_notification("🚫 Спам!", reason)
                    self.log("📤 Перемещено в папку Spam")
                else:
                    self.log("✅ Не спам")

            except Exception as e:
                self.log(f"⚠️ Ошибка обработки: {e}")

        self.log(f"\n✅ Проверено: {len(mail_ids)} | Спам: {spam_count}")
        checker.imap.logout()
        checker.smtp.quit()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    LoginWindow().run()
