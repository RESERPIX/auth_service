# Используем Go 1.22 Alpine
FROM golang:1.22-alpine AS builder

# Устанавливаем необходимые пакеты
RUN apk add --no-cache git bash

# Создаём рабочую директорию
WORKDIR /app

# Копируем go.mod и go.sum и ставим зависимости
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь проект
COPY . .

# Сборка бинарника
RUN go build -o auth-service ./cmd/auth

# Финальный минимальный образ
FROM alpine:3.18
WORKDIR /app

# Копируем бинарник из builder
COPY --from=builder /app/auth-service .

# Копируем конфиги
COPY configs ./configs

# Указываем команду запуска
CMD ["./auth-service"]
