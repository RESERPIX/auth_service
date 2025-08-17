# 🔐 Auth Service

Микросервис аутентификации и авторизации на Go с gRPC API, поддерживающий JWT токены, OAuth провайдеры, двухфакторную аутентификацию и многое другое.

## ✨ Возможности

- 🔑 **JWT аутентификация** с access и refresh токенами
- 📧 **Email верификация** через SMTP
- 📱 **SMS верификация** через SMS.ru, Twilio
- 🌐 **OAuth интеграция** с Yandex, Mail.ru, VK, Госуслуги
- 🔒 **Двухфакторная аутентификация** (2FA)
- 🚫 **Rate limiting** и защита от брутфорса
- 📊 **Аудит действий** пользователей
- 🐳 **Docker поддержка** с docker-compose
- 📝 **Структурированное логирование** через Zap

## 🏗️ Архитектура

```
auth_service/
├── cmd/                    # Точки входа
│   ├── auth/              # Сервер аутентификации
│   └── client/            # Тестовый клиент
├── internal/               # Внутренняя логика
│   ├── app/               # Модели и gRPC сервер
│   ├── config/            # Конфигурация
│   ├── db/                # База данных
│   ├── middleware/        # Промежуточное ПО
│   ├── pb/                # Protobuf файлы
│   └── services/          # Бизнес-логика
├── pkg/                   # Публичные пакеты
│   └── utils/             # Утилиты
├── proto/                 # Protobuf схемы
├── configs/               # Конфигурационные файлы
└── docker/                # Docker файлы
```

## 🚀 Быстрый старт

### Предварительные требования

- Go 1.24+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (опционально)

### Локальный запуск

1. **Клонирование репозитория**
   ```bash
   git clone https://github.com/RESERPIX/auth_service.git
   cd auth_service
   ```

2. **Установка зависимостей**
   ```bash
   go mod download
   go mod tidy
   ```

3. **Настройка базы данных**
   ```bash
   # Создайте базу данных PostgreSQL
   createdb authdb
   
   # Или используйте Docker
   docker run -d --name postgres \
     -e POSTGRES_USER=authuser \
     -e POSTGRES_PASSWORD=authpass \
     -e POSTGRES_DB=authdb \
     -p 5432:5432 \
     postgres:15
   ```

4. **Настройка Redis**
   ```bash
   # Или используйте Docker
   docker run -d --name redis \
     -p 6379:6379 \
     redis:7-alpine
   ```

5. **Настройка конфигурации**
   ```bash
   cp configs/config.yaml configs/config.local.yaml
   # Отредактируйте config.local.yaml под ваши нужды
   ```

6. **Запуск сервера**
   ```bash
   go run ./cmd/auth
   ```

### Docker запуск

```bash
# Запуск всех сервисов
docker-compose -f docker/docker-compose.yaml up -d

# Просмотр логов
docker-compose -f docker/docker-compose.yaml logs -f

# Остановка
docker-compose -f docker/docker-compose.yaml down
```

## 🛠️ Использование Makefile

```bash
# Показать все команды
make help

# Сборка
make build

# Запуск сервера
make run

# Запуск в Docker
make docker-run

# Тесты
make test

# Очистка
make clean
```

## 📡 API Endpoints

### gRPC методы

- `Register` - Регистрация пользователя
- `Login` - Вход в систему
- `RefreshToken` - Обновление токенов
- `Logout` - Выход из системы
- `SendVerificationCode` - Отправка кода верификации
- `VerifyCode` - Проверка кода верификации
- `RequestPasswordReset` - Запрос сброса пароля
- `ResetPassword` - Сброс пароля
- `ValidateToken` - Валидация токена

### Пример использования

```go
package main

import (
    "context"
    "log"
    
    pb "github.com/RESERPIX/auth_service/internal/pb/proto/auth"
    "google.golang.org/grpc"
)

func main() {
    conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    client := pb.NewAuthServiceClient(conn)
    
    // Регистрация
    resp, err := client.Register(context.Background(), &pb.RegisterRequest{
        Email:    "user@example.com",
        Password: "securepassword123",
        FullName: "John Doe",
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("User registered: %s", resp.Message)
}
```

## ⚙️ Конфигурация

Основные настройки в `configs/config.yaml`:

- **Server**: хост, порт, таймауты
- **Database**: PostgreSQL настройки
- **Redis**: настройки кеша
- **JWT**: секреты и TTL токенов
- **Email**: SMTP настройки
- **SMS**: провайдеры SMS
- **OAuth**: настройки OAuth провайдеров
- **Security**: настройки безопасности
- **Logging**: уровень и формат логов

## 🔒 Безопасность

- **BCrypt** для хеширования паролей
- **JWT** с коротким TTL для access токенов
- **Rate limiting** для защиты от брутфорса
- **reCAPTCHA** для защиты форм
- **Аудит** всех действий пользователей
- **Валидация** входных данных

## 🧪 Тестирование

```bash
# Запуск всех тестов
go test ./...

# Тесты с покрытием
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Тесты конкретного пакета
go test ./internal/services/...
```

## 📊 Мониторинг

- **Health checks** для всех сервисов
- **Structured logging** через Zap
- **Metrics** (планируется)
- **Tracing** (планируется)

## 🚀 Развертывание

### Production

1. **Настройте переменные окружения**
2. **Измените JWT секреты**
3. **Включите SSL для базы данных**
4. **Настройте брандмауэр**
5. **Используйте reverse proxy (nginx/traefik)**

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        ports:
        - containerPort: 50051
```

## 🤝 Вклад в проект

1. Fork репозитория
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📝 Лицензия

Этот проект лицензирован под MIT License - см. файл [LICENSE](LICENSE) для деталей.

## 🆘 Поддержка

Если у вас есть вопросы или проблемы:

- Создайте Issue в GitHub
- Обратитесь к команде разработки
- Проверьте документацию

## 🔮 Roadmap

- [ ] GraphQL API
- [ ] WebSocket поддержка
- [ ] Push уведомления
- [ ] Биометрическая аутентификация
- [ ] SAML интеграция
- [ ] OpenID Connect
- [ ] Микросервисная архитектура
- [ ] Kubernetes deployment
- [ ] Prometheus метрики
- [ ] Jaeger tracing

---

**Сделано с ❤️ командой RESERPIX**
