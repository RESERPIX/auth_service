package app

import (
	"context"

	pb "github.com/RESERPIX/auth_service/internal/pb/proto/auth"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	AuthApp *AuthApp
}

// Реализация Login
func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	token, err := s.AuthApp.Login(ctx, req.Login, req.Password)
	if err != nil {
		return nil, err
	}

	return &pb.LoginResponse{
		AccessToken: token,
		ExpiresIn:   uint64(s.AuthApp.JWTTTL.Seconds()),
	}, nil
}
