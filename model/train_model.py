import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib
import os
import email
import logging
from email.parser import BytesParser
from email.policy import default

# Настройка логирования
#logging.basicConfig(
#   level=logging.INFO,
#  format='%(asctime)s - %(levelname)s - %(message)s',
# handlers=[
#        logging.FileHandler('model_training.log'),
#        logging.StreamHandler()
#    ]
#)

def extract_email_content(email_file):
    """Извлекает содержимое письма из .eml или .txt."""
    try:
        if email_file.endswith('.eml'):
            with open(email_file, 'rb') as f:
                parser = BytesParser(policy=default)
                msg = parser.parse(f)
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                                break
                            except Exception:
                                continue
                        elif part.get_content_type() == "text/html" and not body:
                            try:
                                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                            except Exception:
                                continue
                else:
                    try:
                        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
                    except Exception:
                        body = msg.get_payload()
                subject = msg.get('subject', '') or ''
                content = f"{subject}\n{body}"
                return content.strip()
        else:
            with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read().strip()
    except Exception as e:
        logging.error(f"Ошибка при обработке файла {email_file}: {str(e)}")
        return ""

def load_dataset():
    """Загружает датасет из папок spam и ham."""
    X = []
    y = []

    spam_dir = 'data/spam'
    ham_dir = 'data/ham'

    for label, directory in [(1, spam_dir), (0, ham_dir)]:
        if os.path.exists(directory):
            logging.info(f"Загрузка писем из {directory}")
            for filename in os.listdir(directory):
                if filename.endswith(('.eml', '.txt')):
                    content = extract_email_content(os.path.join(directory, filename))
                    if content:
                        X.append(content)
                        y.append(label)
        else:
            logging.warning(f"Папка {directory} не найдена")

    return X, y

def train_model():
    """Обучает модель для определения спама."""
    logging.info("Начало обучения модели")

    X, y = load_dataset()
    if not X or not y:
        logging.error("Не удалось загрузить данные для обучения")
        return False

    logging.info(f"Загружено {len(X)} писем (спам: {sum(y)}, не спам: {len(y)-sum(y)})")

    try:
        model = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                stop_words='english'
            )),
            ('classifier', MultinomialNB())
        ])

        model.fit(X, y)

        model_dir = '.app_files'
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, 'spam_model.pkl')
        joblib.dump(model, model_path)
        logging.info(f"Модель успешно обучена и сохранена в файл: {model_path}")

        train_accuracy = model.score(X, y)
        logging.info(f"Точность на обучающей выборке: {train_accuracy:.2%}")
        return True

    except Exception as e:
        logging.error(f"Ошибка при обучении модели: {str(e)}")
        return False

if __name__ == "__main__":
    print("=== Обучение модели для определения спама ===")

    if not os.path.exists('data/spam') or not os.path.exists('data/ham'):
        print("❌ Ошибка: не найдены папки 'spam' и/или 'ham' с обучающими данными")
        exit(1)

    print("\nНачало обучения...")
    if train_model():
        print("\n✅ Модель успешно обучена и сохранена в файл 'spam_model.pkl'")
    else:
        print("\n❌ Ошибка при обучении модели")
