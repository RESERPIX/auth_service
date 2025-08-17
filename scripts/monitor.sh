#!/bin/bash

# Скрипт для мониторинга auth_service
# Использование: ./scripts/monitor.sh [interval]

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Интервал проверки (по умолчанию 30 секунд)
INTERVAL=${1:-30}

# Функция для логирования
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Функция для проверки статуса сервиса
check_service() {
    local service_name=$1
    local command=$2
    
    if pgrep -f "$command" > /dev/null; then
        echo -e "${GREEN}✓${NC} $service_name запущен"
        return 0
    else
        echo -e "${RED}✗${NC} $service_name не запущен"
        return 1
    fi
}

# Функция для проверки портов
check_port() {
    local port=$1
    local service=$2
    
    if netstat -tuln 2>/dev/null | grep ":$port " > /dev/null; then
        echo -e "${GREEN}✓${NC} $service слушает на порту $port"
        return 0
    else
        echo -e "${RED}✗${NC} $service не слушает на порту $port"
        return 1
    fi
}

# Функция для проверки базы данных
check_database() {
    if pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} PostgreSQL доступен"
        return 0
    else
        echo -e "${RED}✗${NC} PostgreSQL недоступен"
        return 1
    fi
}

# Функция для проверки Redis
check_redis() {
    if redis-cli ping > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Redis доступен"
        return 0
    else
        echo -e "${RED}✗${NC} Redis недоступен"
        return 1
    fi
}

# Функция для проверки использования ресурсов
check_resources() {
    echo -e "${BLUE}📊 Использование ресурсов:${NC}"
    
    # CPU
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    echo -e "  CPU: ${YELLOW}${cpu_usage}%${NC}"
    
    # Память
    memory_info=$(free -m | grep Mem)
    total_mem=$(echo $memory_info | awk '{print $2}')
    used_mem=$(echo $memory_info | awk '{print $3}')
    mem_usage=$((used_mem * 100 / total_mem))
    echo -e "  Память: ${YELLOW}${mem_usage}%${NC} (${used_mem}MB / ${total_mem}MB)"
    
    # Диск
    disk_usage=$(df -h / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    echo -e "  Диск: ${YELLOW}${disk_usage}%${NC}"
}

# Функция для проверки логов
check_logs() {
    echo -e "${BLUE}📝 Последние логи:${NC}"
    
    if [ -f "auth.log" ]; then
        tail -5 auth.log | while read line; do
            if echo "$line" | grep -q "ERROR\|FATAL"; then
                echo -e "  ${RED}$line${NC}"
            elif echo "$line" | grep -q "WARN"; then
                echo -e "  ${YELLOW}$line${NC}"
            else
                echo -e "  $line"
            fi
        done
    else
        echo -e "  ${YELLOW}Файл логов не найден${NC}"
    fi
}

# Основная функция мониторинга
main() {
    log "${BLUE}🚀 Запуск мониторинга auth_service${NC}"
    log "Интервал проверки: ${INTERVAL} секунд"
    echo
    
    while true; do
        echo -e "${BLUE}🔍 Проверка статуса сервисов...${NC}"
        echo
        
        # Проверка сервисов
        check_service "Auth Service" "auth"
        check_service "PostgreSQL" "postgres"
        check_service "Redis" "redis"
        echo
        
        # Проверка портов
        check_port 50051 "gRPC Server"
        check_port 5432 "PostgreSQL"
        check_port 6379 "Redis"
        echo
        
        # Проверка баз данных
        check_database
        check_redis
        echo
        
        # Проверка ресурсов
        check_resources
        echo
        
        # Проверка логов
        check_logs
        echo
        
        # Разделитель
        echo "----------------------------------------"
        echo
        
        # Ожидание до следующей проверки
        sleep $INTERVAL
    done
}

# Обработка сигналов
trap 'log "${YELLOW}⚠️  Мониторинг остановлен${NC}"; exit 0' INT TERM

# Запуск основной функции
main
