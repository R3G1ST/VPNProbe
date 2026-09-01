<div align="center">

# 🔒 VPNProbe

**Проверка VPN подписок и протоколов**

[![.NET](https://img.shields.io/badge/.NET-8.0-purple?logo=dotnet)](https://dotnet.microsoft.com/)
[![WPF](https://img.shields.io/badge/WPF-8.0-blue)](https://learn.microsoft.com/dotnet/desktop/wpf/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Release](https://img.shields.io/github/v/release/R3G1ST/VPNProbe?color=00ff88)](https://github.com/R3G1ST/VPNProbe/releases)

<img src="app.png" width="120"/>

</div>

---

## ✨ Возможности

- 🔍 **Проверка серверов** — Ping, Port, TLS, Proxy (sing-box), DPI
- 📋 **Управление подписками** — сохранение, выбор, авто-имя
- 🎯 **Реал-тайм модалка** — живой прогресс с таблицей результатов
- 📊 **Аудит провайдера** — IP, DPI детекция, скорость, bufferbloat, DNS, гео-блокировка
- 🎨 **Тёмная тема** — cyber-стиль, антиалиасинг, закруглённые углы
- 📦 **Установщик** — NSIS, ярлыки, деинсталлятор

## 📸 Скриншоты

<div align="center">
<img src="https://via.placeholder.com/800x450/030306/00ff88?text=VPNProbe+Screenshot" width="100%"/>
</div>

## 🚀 Скачать

| | |
|---|---|
| **Инсталлер** | [VPNProbe-Setup-1.0.1.exe](https://github.com/R3G1ST/VPNProbe/releases/download/v1.0.1/VPNProbe-Setup-1.0.1.exe) (75 MB) |
| **Требования** | Windows 10/11 x64 |

## 🛠️ Сборка из исходников

```bash
# Клонировать
git clone https://github.com/R3G1ST/VPNProbe.git
cd VPNProbe

# Собрать
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true

# Или запустить в dev-режиме
dotnet run
```

## 📋 Проверки

| Проверка | Описание |
|----------|----------|
| **Ping** | ICMP ping до сервера |
| **Port/TLS** | TCP порт + TLS/Reality handshake |
| **Proxy** | Подключение через sing-box |
| **DPI** | Детекция блокировки DPI |

## 🏗️ Структура проекта

```
VPNProbe/
├── App.xaml              # Тёмная тема, стили
├── MainWindow.xaml       # Главное окно
├── Models/
│   ├── ServerInfo.cs     # Модели серверов
│   └── AuditModels.cs    # Модели аудита
├── Services/
│   ├── SubscriptionParser.cs   # Парсинг подписок
│   ├── PingChecker.cs          # ICMP ping
│   ├── PortTlsChecker.cs       # Port + TLS/Reality
│   ├── ProxyChecker.cs         # sing-box проверка
│   ├── DpiChecker.cs           # DPI детекция
│   ├── AuditServices.cs        # Аудит провайдера
│   └── SubscriptionManager.cs  # Сохранение ссылок
└── Views/
    ├── CheckProgressWindow.xaml    # Модалка проверки
    └── SavedLinksWindow.xaml       # Сохранённые ссылки
```

## ⚙️ Используемые технологии

- **C# / .NET 8** — WPF приложение
- **sing-box** — проверка прокси
- **Open-Meteo** — API погоды (для аудита)
- **NSIS** — установщик

## 📄 Лицензия

MIT License — используй свободно.

---

<div align="center">

**R3G1ST** • [GitHub](https://github.com/R3G1ST)

</div>
