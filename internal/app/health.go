package app

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// HealthStatus представляет статус здоровья сервиса
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Uptime    string            `json:"uptime"`
	Services  map[string]Status `json:"services"`
}

// Status представляет статус отдельного сервиса
type Status struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// HealthChecker проверяет здоровье сервиса
type HealthChecker struct {
	db    *gorm.DB
	redis *redis.Client
	start time.Time
}

// NewHealthChecker создает новый экземпляр HealthChecker
func NewHealthChecker(db *gorm.DB, redis *redis.Client) *HealthChecker {
	return &HealthChecker{
		db:    db,
		redis: redis,
		start: time.Now(),
	}
}

// CheckHealth проверяет общее здоровье сервиса
func (h *HealthChecker) CheckHealth() *HealthStatus {
	status := &HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Uptime:    h.getUptime(),
		Services:  make(map[string]Status),
	}

	// Проверка базы данных
	dbStatus := h.checkDatabase()
	status.Services["database"] = dbStatus

	// Проверка Redis
	redisStatus := h.checkRedis()
	status.Services["redis"] = redisStatus

	// Проверка общего статуса
	if dbStatus.Status == "unhealthy" || redisStatus.Status == "unhealthy" {
		status.Status = "unhealthy"
	}

	return status
}

// checkDatabase проверяет здоровье базы данных
func (h *HealthChecker) checkDatabase() Status {
	start := time.Now()
	
	// Проверяем подключение к базе данных
	sqlDB, err := h.db.DB()
	if err != nil {
		return Status{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Failed to get DB instance: %v", err),
		}
	}

	// Проверяем ping
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := sqlDB.PingContext(ctx); err != nil {
		return Status{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Database ping failed: %v", err),
		}
	}

	// Проверяем статистику подключений
	stats := sqlDB.Stats()
	latency := time.Since(start)

	return Status{
		Status:  "healthy",
		Message: fmt.Sprintf("Connected. Open connections: %d, InUse: %d", stats.OpenConnections, stats.InUse),
		Latency: latency.String(),
	}
}

// checkRedis проверяет здоровье Redis
func (h *HealthChecker) checkRedis() Status {
	start := time.Now()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Проверяем ping
	if err := h.redis.Ping(ctx).Err(); err != nil {
		return Status{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Redis ping failed: %v", err),
		}
	}

	// Проверяем базовые операции
	key := "health_check_test"
	value := "test_value"
	
	if err := h.redis.Set(ctx, key, value, time.Minute).Err(); err != nil {
		return Status{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Redis write failed: %v", err),
		}
	}

	if err := h.redis.Del(ctx, key).Err(); err != nil {
		return Status{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Redis delete failed: %v", err),
		}
	}

	latency := time.Since(start)

	return Status{
		Status:  "healthy",
		Message: "Connected and operational",
		Latency: latency.String(),
	}
}

// getUptime возвращает время работы сервиса
func (h *HealthChecker) getUptime() string {
	uptime := time.Since(h.start)
	
	if uptime < time.Minute {
		return fmt.Sprintf("%.0fs", uptime.Seconds())
	} else if uptime < time.Hour {
		return fmt.Sprintf("%.0fm", uptime.Minutes())
	} else if uptime < 24*time.Hour {
		return fmt.Sprintf("%.0fh", uptime.Hours())
	} else {
		days := int(uptime.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	}
}

// GetDetailedStats возвращает детальную статистику
func (h *HealthChecker) GetDetailedStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	// Статистика базы данных
	if sqlDB, err := h.db.DB(); err == nil {
		dbStats := sqlDB.Stats()
		stats["database"] = map[string]interface{}{
			"max_open_connections": dbStats.MaxOpenConnections,
			"open_connections":     dbStats.OpenConnections,
			"in_use":              dbStats.InUse,
			"idle":                dbStats.Idle,
			"wait_count":          dbStats.WaitCount,
			"wait_duration":       dbStats.WaitDuration.String(),
			"max_idle_closed":     dbStats.MaxIdleClosed,
			"max_lifetime_closed": dbStats.MaxLifetimeClosed,
		}
	}

	// Статистика Redis
	ctx := context.Background()
	info, err := h.redis.Info(ctx).Result()
	if err == nil {
		stats["redis_info"] = info
	}

	// Общая статистика
	stats["uptime"] = h.getUptime()
	stats["start_time"] = h.start
	stats["current_time"] = time.Now()

	return stats
}
