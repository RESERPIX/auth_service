package main

import (
	"log"
	"net"
	"time"

	"github.com/RESERPIX/auth_service/internal/app"
	"github.com/RESERPIX/auth_service/internal/db"
	pb "github.com/RESERPIX/auth_service/internal/pb/proto/auth"

	"google.golang.org/grpc"
)

func main() {
	// подключаем БД
	dbConn := db.ConnectPostgres("localhost", "5432", "postgres", "postgres", "auth_service")

	// создаём AuthApp
	authApp := &app.AuthApp{
		DB:        dbConn,
		JWTSecret: "supersecretkey",
		JWTTTL:    time.Hour,
	}

	// создаём gRPC сервер
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, &app.AuthServer{AuthApp: authApp})

	log.Println("Auth service is running on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
