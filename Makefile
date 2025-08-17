.PHONY: help build run test clean proto docker-build docker-run

# Переменные
BINARY_NAME=auth
CLIENT_NAME=client
BUILD_DIR=build
DOCKER_COMPOSE=docker/docker-compose.yaml

# Цвета для вывода
GREEN=\033[0;32m
NC=\033[0m # No Color

help: ## Показать справку
	@echo "$(GREEN)Доступные команды:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Собрать сервер и клиент
	@mkdir -p $(BUILD_DIR)
	@echo "$(GREEN)Сборка сервера...$(NC)"
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/auth
	@echo "$(GREEN)Сборка клиента...$(NC)"
	@go build -o $(BUILD_DIR)/$(CLIENT_NAME) ./cmd/client
	@echo "$(GREEN)Сборка завершена!$(NC)"

run: ## Запустить сервер
	@echo "$(GREEN)Запуск сервера...$(NC)"
	@go run ./cmd/auth

run-client: ## Запустить клиент
	@echo "$(GREEN)Запуск клиента...$(NC)"
	@go run ./cmd/client

test: ## Запустить тесты
	@echo "$(GREEN)Запуск тестов...$(NC)"
	@go test -v ./internal/services/...

test-all: ## Запустить все тесты
	@echo "$(GREEN)Запуск всех тестов...$(NC)"
	@go test -v ./...

test-coverage: ## Запустить тесты с покрытием
	@echo "$(GREEN)Запуск тестов с покрытием...$(NC)"
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out

clean: ## Очистить сборки
	@echo "$(GREEN)Очистка...$(NC)"
	@rm -rf $(BUILD_DIR)
	@go clean

proto: ## Генерировать protobuf файлы
	@echo "$(GREEN)Генерация protobuf...$(NC)"
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/auth/auth.proto

deps: ## Установить зависимости
	@echo "$(GREEN)Установка зависимостей...$(NC)"
	@go mod download
	@go mod tidy

docker-build: ## Собрать Docker образ
	@echo "$(GREEN)Сборка Docker образа...$(NC)"
	@docker build -f docker/Dockerfile -t auth-service .

docker-run: ## Запустить в Docker
	@echo "$(GREEN)Запуск в Docker...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE) up -d

docker-stop: ## Остановить Docker
	@echo "$(GREEN)Остановка Docker...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE) down

docker-logs: ## Показать логи Docker
	@docker-compose -f $(DOCKER_COMPOSE) logs -f

lint: ## Проверить код линтером
	@echo "$(GREEN)Проверка линтером...$(NC)"
	@golangci-lint run

fmt: ## Форматировать код
	@echo "$(GREEN)Форматирование кода...$(NC)"
	@go fmt ./...

vet: ## Проверить код go vet
	@echo "$(GREEN)Проверка go vet...$(NC)"
	@go vet ./...

health: ## Проверить здоровье сервиса
	@echo "$(GREEN)Проверка здоровья сервиса...$(NC)"
	@curl -s http://localhost:50051/health || echo "Сервис не запущен"

monitor: ## Запустить мониторинг сервиса
	@echo "$(GREEN)Запуск мониторинга...$(NC)"
	@./scripts/monitor.sh

dev: ## Запустить в режиме разработки
	@echo "$(GREEN)Запуск в режиме разработки...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE) up -d postgres redis
	@sleep 5
	@go run ./cmd/auth
