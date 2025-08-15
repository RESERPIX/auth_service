package db

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"
)

func ConnectRedis(addr, password string, dbNum int) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       dbNum,
	})

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	return rdb
}
