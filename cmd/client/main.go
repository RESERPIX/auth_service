package main

import (
	"context"
	"log"
	"time"

	pb "github.com/RESERPIX/auth_service/internal/pb/proto/auth"
	"google.golang.org/grpc"
)

func main() {
	// Подключаемся к серверу
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewAuthServiceClient(conn)

	// Тестируем Login
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.Login(ctx, &pb.LoginRequest{
		Login:    "test@example.com",
		Password: "123456",
	})
	if err != nil {
		log.Fatalf("could not login: %v", err)
	}

	log.Printf("Login response: token=%s, expires_in=%d", resp.AccessToken, resp.ExpiresIn)
}
