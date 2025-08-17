# Auth Service Integration Guide

This guide provides instructions for integrating the Auth Service with a web application using gRPC-web through Envoy proxy.

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Available Auth Service Methods](#available-auth-service-methods)
3. [Frontend Integration](#frontend-integration)
4. [Example Implementation](#example-implementation)
5. [Error Handling](#error-handling)
6. [Security Considerations](#security-considerations)

## Architecture Overview

The Auth Service is implemented as a gRPC service that communicates over HTTP/2. For web browsers that don't support HTTP/2 directly, we use Envoy proxy as a gRPC-web bridge.

```
Web Browser → gRPC-web → Envoy Proxy → gRPC Service (Auth Service)
```

The Envoy proxy is configured to listen on port 8080 and forward requests to the Auth Service running on port 50051.

## Available Auth Service Methods

The Auth Service provides the following methods:

### Authentication Methods

1. **Register** - Register a new user account
2. **Login** - Authenticate a user and obtain access/refresh tokens
3. **RefreshToken** - Refresh an expired access token using a refresh token
4. **Logout** - Invalidate a user session

### Verification Methods

1. **SendVerificationCode** - Send a verification code via email or SMS
2. **VerifyCode** - Verify a code sent to the user

### Password Management

1. **RequestPasswordReset** - Request a password reset link
2. **ResetPassword** - Reset a user's password using a reset token

### Two-Factor Authentication (2FA)

1. **EnableTwoFactor** - Enable two-factor authentication for a user
2. **DisableTwoFactor** - Disable two-factor authentication for a user
3. **VerifyTwoFactor** - Verify a 2FA code

### OAuth Integration

1. **LoginWithProvider** - Authenticate using an external OAuth provider (Yandex, Mail.ru, VK, Gosuslugi)

### User Management

1. **GetUserProfile** - Retrieve the current user's profile information
2. **UpdateUserProfile** - Update the current user's profile information
3. **ChangePassword** - Change the current user's password

### Token Validation

1. **ValidateToken** - Validate an access token

## Frontend Integration

### Prerequisites

1. Install the required npm packages:
   ```bash
   npm install grpc-web google-protobuf
   ```

2. Generate the gRPC-web client code from the proto file:
   ```bash
   protoc -I=. auth.proto \
     --js_out=import_style=commonjs:. \
     --grpc-web_out=import_style=commonjs,mode=grpcwebtext:.
   ```

### Client Configuration

Create a gRPC-web client instance pointing to your Envoy proxy:

```javascript
const {AuthServiceClient} = require('./auth_grpc_web_pb');
const {RegisterRequest, LoginRequest} = require('./auth_pb');

// Create client pointing to Envoy proxy
const client = new AuthServiceClient('http://localhost:8080');
```

### Making gRPC-web Calls

All gRPC-web calls follow the same pattern:

```javascript
// Create request object
const request = new RequestType();
request.setField(value);

// Make the call
const call = client.methodName(request, metadata, callback);

// For unary calls, you can also use promises
client.methodName(request, metadata)
  .then(response => {
    // Handle successful response
  })
  .catch(error => {
    // Handle error
  });
```

## Example Implementation

### User Registration

```javascript
function registerUser(fullName, email, password) {
  const request = new RegisterRequest();
  request.setFullName(fullName);
  request.setEmail(email);
  request.setPassword(password);
  request.setConfirmPassword(password);
  request.setAcceptTerms(true);
  
  return new Promise((resolve, reject) => {
    client.register(request, {}, (err, response) => {
      if (err) {
        reject(err);
      } else {
        resolve(response.toObject());
      }
    });
  });
}
```

### User Login

```javascript
function loginUser(login, password) {
  const request = new LoginRequest();
  request.setLogin(login);
  request.setPassword(password);
  
  return new Promise((resolve, reject) => {
    client.login(request, {}, (err, response) => {
      if (err) {
        reject(err);
      } else {
        // Store tokens in localStorage or secure cookie
        localStorage.setItem('accessToken', response.getAccessToken());
        localStorage.setItem('refreshToken', response.getRefreshToken());
        resolve(response.toObject());
      }
    });
  });
}
```

### Token Validation

```javascript
function validateToken(token) {
  const request = new ValidateTokenRequest();
  request.setAccessToken(token);
  
  return new Promise((resolve, reject) => {
    client.validateToken(request, {}, (err, response) => {
      if (err) {
        reject(err);
      } else {
        resolve(response.toObject());
      }
    });
  });
}
```

### Protected Route Access

```javascript
function makeAuthenticatedRequest() {
  const token = localStorage.getItem('accessToken');
  
  if (!token) {
    // Redirect to login
    window.location.href = '/login';
    return;
  }
  
  // Validate token before making request
  validateToken(token)
    .then(response => {
      if (response.valid) {
        // Token is valid, proceed with request
        // Add token to metadata for authenticated requests
        const metadata = {'authorization': `Bearer ${token}`};
        // Make your authenticated gRPC-web call here
      } else {
        // Token invalid, redirect to login
        window.location.href = '/login';
      }
    })
    .catch(error => {
      console.error('Token validation failed:', error);
      window.location.href = '/login';
    });
}
```

## Error Handling

gRPC-web uses standard gRPC status codes. Common error handling pattern:

```javascript
client.methodName(request, metadata)
  .then(response => {
    // Handle successful response
  })
  .catch(error => {
    switch (error.code) {
      case grpcWeb.StatusCode.UNAUTHENTICATED:
        // Redirect to login
        break;
      case grpcWeb.StatusCode.PERMISSION_DENIED:
        // Show access denied message
        break;
      case grpcWeb.StatusCode.INVALID_ARGUMENT:
        // Show validation error
        break;
      default:
        // Handle other errors
        console.error('An error occurred:', error.message);
    }
  });
```

## Security Considerations

1. **Token Storage**: Store access tokens in memory when possible. For longer sessions, use secure, httpOnly cookies rather than localStorage.

2. **Token Refresh**: Implement automatic token refresh before expiration:
   ```javascript
   function refreshToken() {
     const refreshToken = localStorage.getItem('refreshToken');
     if (!refreshToken) return;
     
     const request = new RefreshTokenRequest();
     request.setRefreshToken(refreshToken);
     
     client.refreshToken(request, {}, (err, response) => {
       if (!err) {
         localStorage.setItem('accessToken', response.getAccessToken());
         localStorage.setItem('refreshToken', response.getRefreshToken());
       }
     });
   }
   ```

3. **CSRF Protection**: When using cookies for token storage, implement CSRF protection.

4. **HTTPS**: Always use HTTPS in production to protect tokens in transit.

5. **Rate Limiting**: The service implements rate limiting to prevent abuse.

6. **Input Validation**: Always validate user input on both client and server sides.

## Running the Service

1. Start the Auth Service:
   ```bash
   go run cmd/auth/main.go
   ```

2. Start Envoy Proxy:
   ```bash
   envoy -c etc/envoy/envoy.yaml
   ```

3. The service will be available at `http://localhost:8080` for gRPC-web calls.

## Testing

Use the provided web-test interface to test the integration:
1. Open `web-test/index.html` in a browser
2. Use the forms to test registration, login, and other functionality
3. Check browser console for detailed logs

Note: The current web-test implementation uses mock functions. Replace these with actual gRPC-web calls for real integration.