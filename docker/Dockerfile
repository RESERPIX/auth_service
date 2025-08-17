# Многоэтапная сборка для оптимизации размера образа
FROM golang:1.22-alpine AS builder

# Устанавливаем необходимые пакеты для сборки
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    gcc \
    musl-dev

# Создаём пользователя для безопасности
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Создаём рабочую директорию
WORKDIR /build

# Копируем файлы зависимостей
COPY go.mod go.sum ./

# Скачиваем зависимости (кешируется при изменении только кода)
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение с оптимизацией
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o auth-service \
    ./cmd/auth

# Установка grpc_health_probe для health checks
RUN GRPC_HEALTH_PROBE_VERSION=v0.4.19 && \
    wget -qO/bin/grpc_health_probe \
    https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe

# Финальный минимальный образ
FROM scratch

# Копируем сертификаты CA
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Копируем информацию о часовых поясах
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Копируем пользователя
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Копируем приложение
COPY --from=builder /build/auth-service /app/auth-service

# Копируем grpc_health_probe
COPY --from=builder /bin/grpc_health_probe /bin/grpc_health_probe

# Копируем конфигурационные файлы
COPY --from=builder /build/configs /app/configs

# Устанавливаем рабочую директорию
WORKDIR /app

# Используем непривилегированного пользователя
USER appuser:appgroup

# Открываем порт
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/bin/grpc_health_probe", "-addr=localhost:50051"]

# Запуск приложения
ENTRYPOINT ["./auth-service"]