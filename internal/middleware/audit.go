package middleware

import (
	"context"
	"encoding/json"
	"time"

	"github.com/RESERPIX/auth_service/internal/app"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gorm.io/gorm"
)

// AuditConfig конфигурация для аудита
type AuditConfig struct {
	Enabled     bool
	LogToDB     bool
	LogToConsole bool
	ExcludeMethods []string
}

// AuditMiddleware middleware для аудита действий пользователей
type AuditMiddleware struct {
	config AuditConfig
	logger *zap.Logger
	db     *gorm.DB
}

// NewAuditMiddleware создает новый экземпляр AuditMiddleware
func NewAuditMiddleware(config AuditConfig, logger *zap.Logger, db *gorm.DB) *AuditMiddleware {
	return &AuditMiddleware{
		config: config,
		logger: logger,
		db:     db,
	}
}

// UnaryServerInterceptor возвращает unary interceptor для аудита
func (am *AuditMiddleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		
		// Если аудит отключен, пропускаем
		if !am.config.Enabled {
			return handler(ctx, req)
		}

		// Проверяем, не исключен ли метод из аудита
		if am.isExcludedMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		// Извлекаем информацию о пользователе и запросе
		userID, userAgent, ipAddress := am.extractRequestInfo(ctx)
		
		// Выполняем запрос
		resp, err := handler(ctx, req)
		
		// Определяем результат
		result := "success"
		if err != nil {
			result = "failed"
		}

		// Логируем действие
		am.logAction(ctx, info.FullMethod, userID, userAgent, ipAddress, result, startTime, err)

		return resp, err
	}
}

// isExcludedMethod проверяет, исключен ли метод из аудита
func (am *AuditMiddleware) isExcludedMethod(method string) bool {
	for _, excluded := range am.config.ExcludeMethods {
		if method == excluded {
			return true
		}
	}
	return false
}

// extractRequestInfo извлекает информацию о запросе
func (am *AuditMiddleware) extractRequestInfo(ctx context.Context) (userID uint, userAgent, ipAddress string) {
	// Получаем metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		// User-Agent
		if ua := md.Get("user-agent"); len(ua) > 0 {
			userAgent = ua[0]
		}
		
		// IP адрес
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			ipAddress = xff[0]
		} else if xri := md.Get("x-real-ip"); len(xri) > 0 {
			ipAddress = xri[0]
		}
		
		// User ID (если есть в токене)
		if userIDStr := md.Get("x-user-id"); len(userIDStr) > 0 {
			// Здесь можно распарсить user ID из строки
			// Пока оставляем 0
		}
	}
	
	return userID, userAgent, ipAddress
}

// logAction логирует действие пользователя
func (am *AuditMiddleware) logAction(ctx context.Context, method string, userID uint, userAgent, ipAddress, result string, startTime time.Time, err error) {
	duration := time.Since(startTime)
	
	// Подготавливаем детали
	details := map[string]interface{}{
		"method":     method,
		"duration":   duration.String(),
		"user_agent": userAgent,
		"ip_address": ipAddress,
		"timestamp":  startTime,
	}
	
	if err != nil {
		details["error"] = err.Error()
	}

	// Логируем в консоль
	if am.config.LogToConsole {
		am.logger.Info("audit_log",
			zap.String("method", method),
			zap.Uint("user_id", userID),
			zap.String("result", result),
			zap.Duration("duration", duration),
			zap.String("user_agent", userAgent),
			zap.String("ip_address", ipAddress),
			zap.Error(err),
		)
	}

	// Логируем в базу данных
	if am.config.LogToDB && am.db != nil {
		go am.saveAuditLog(ctx, method, userID, userAgent, ipAddress, result, details)
	}
}

// saveAuditLog сохраняет запись аудита в базу данных
func (am *AuditMiddleware) saveAuditLog(ctx context.Context, method string, userID uint, userAgent, ipAddress, result string, details map[string]interface{}) {
	// Сериализуем детали в JSON
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		am.logger.Error("Failed to marshal audit details", zap.Error(err))
		return
	}

	// Создаем запись аудита
	auditLog := &app.UserAuditLog{
		UserID:    &userID,
		Action:    method,
		Details:   string(detailsJSON),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   result == "success",
		CreatedAt: time.Now(),
	}

	// Сохраняем в базу данных
	if err := am.db.Create(auditLog).Error; err != nil {
		am.logger.Error("Failed to save audit log", zap.Error(err))
	}
}

// GetAuditLogs возвращает записи аудита для пользователя
func (am *AuditMiddleware) GetAuditLogs(ctx context.Context, userID uint, limit, offset int) ([]app.UserAuditLog, error) {
	var logs []app.UserAuditLog
	
	err := am.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	
	return logs, err
}

// GetAuditLogsByAction возвращает записи аудита по действию
func (am *AuditMiddleware) GetAuditLogsByAction(ctx context.Context, action string, limit, offset int) ([]app.UserAuditLog, error) {
	var logs []app.UserAuditLog
	
	err := am.db.Where("action = ?", action).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	
	return logs, err
}

// GetAuditLogsByIP возвращает записи аудита по IP адресу
func (am *AuditMiddleware) GetAuditLogsByIP(ctx context.Context, ipAddress string, limit, offset int) ([]app.UserAuditLog, error) {
	var logs []app.UserAuditLog
	
	err := am.db.Where("ip_address = ?", ipAddress).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	
	return logs, err
}

// CleanupOldAuditLogs очищает старые записи аудита
func (am *AuditMiddleware) CleanupOldAuditLogs(ctx context.Context, olderThan time.Duration) error {
	cutoffTime := time.Now().Add(-olderThan)
	
	result := am.db.Where("created_at < ?", cutoffTime).Delete(&app.UserAuditLog{})
	if result.Error != nil {
		return result.Error
	}
	
	am.logger.Info("Cleaned up old audit logs",
		zap.Int64("deleted_count", result.RowsAffected),
		zap.Time("cutoff_time", cutoffTime),
	)
	
	return nil
}
