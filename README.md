# 🕵️‍♂️ Smart Business & Contact Scraper

A high-performance asynchronous lead generation tool designed to bypass modern bot protections and intelligently categorize business websites using local LLMs.

## 🚀 Key Features

* **Multi-Stage Fetching Pipeline**:
    * **Level 1: aiohttp** – Lightning-fast raw HTML fetching for unprotected sites.
    * **Level 2: cloudscraper** – Bypasses Cloudflare TLS fingerprinting and basic challenges.
    * **Level 3: Playwright (Stealth)** – Full browser emulation to solve complex JS challenges and decode obfuscated emails.
* **AI-Powered Categorization**: Integrates with **Ollama** (local LLM) to analyze website content and determine the business niche automatically.
* **Tiered Email Extraction**: Prioritizes high-value contacts (e.g., `ceo@`, `advertising@`, `marketing@`) over generic addresses (`info@`).
* **Resilience & Stability**: 
    * **DNS Pre-check**: Skips dead domains before wasting resources.
    * **Batch Processing**: Periodically recreates browser contexts to prevent memory leaks.
    * **Heartbeat Monitor**: Automatically cancels and logs stalled tasks.



## 🛠 Setup & Installation

### 1. Prerequisites
* **Python 3.9+**
* **Ollama** (installed and running)
* **Windows/Linux/macOS**

### 2. Install Dependencies
pip install asyncio aiohttp pandas beautifulsoup4 playwright cloudscraper openai openpyxl
python -m playwright install chromium

# 🕵️‍♂️ Smart Business & Contact Scraper

Профессиональный асинхронный инструмент для поиска лидов, способный обходить современные защиты (Cloudflare) и классифицировать сайты с помощью локальных нейросетей.

## 🚀 Основные возможности

* **Многоуровневый конвейер сбора данных**:
    * **Уровень 1: aiohttp** – Максимальная скорость для незащищенных страниц.
    * **Уровень 2: cloudscraper** – Обход базовой защиты Cloudflare на уровне TLS-отпечатков.
    * **Уровень 3: Playwright (Stealth)** – Эмуляция реального браузера для выполнения JS и расшифровки скрытых email (CF Email Protection).
* **Интеллектуальная классификация**: Интеграция с **Ollama** (локальный LLM) для автоматического определения ниши бизнеса на основе текстового контента.
* **Приоритезация Email**: Система ищет наиболее ценные контакты (`ceo@`, `sales@`, `marketing@`) и ставит их на первое место.
* **Надежность**: 
    * **DNS Pre-check**: Предварительная проверка доступности домена для экономии ресурсов.
    * **Batch Processing**: Перезапуск контекста браузера каждые 10 сайтов для предотвращения утечек памяти.
    * **Heartbeat**: Защита от зависания отдельных задач.



## 🛠 Настройка и установка

### 1. Требования
* **Python 3.9+**
* **Ollama** (установлена и запущена)
* **Chromium** для Playwright

### 2. Установка зависимостей
```bash
pip install asyncio aiohttp pandas beautifulsoup4 playwright cloudscraper openai openpyxl
python -m playwright install chromium
