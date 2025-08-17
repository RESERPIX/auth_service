# Auth Service Test Interface

This is a simple web interface for testing the functionality of the Auth Service microservice.

## Features

The interface includes forms for:

1. **Login** - Authenticate existing users
2. **Registration** - Create new user accounts
3. **Password Reset** - Request and complete password reset
4. **User Profile** - View and update user profile information

## How to Use

1. Open `index.html` in a web browser
2. Use the navigation buttons at the top to switch between different forms
3. Fill out the forms and submit to test the auth service functionality

## Implementation Notes

This interface is designed to communicate with the Auth Service gRPC server. The current implementation includes:

- HTML forms for all major auth functions
- CSS styling for a clean, responsive interface
- JavaScript handling for form submissions and UI interactions
- Local storage for maintaining session state

## Integration with Auth Service

To connect this interface with the actual Auth Service:

1. The Auth Service must be running (default port: 50051)
2. A gRPC-web proxy must be configured to allow browser communication
3. The JavaScript functions in `script.js` need to be updated to make actual gRPC calls instead of the current mock implementations

## Files

- `index.html` - Main HTML file containing all forms
- `styles.css` - CSS styling for the interface
- `script.js` - JavaScript for form handling and API communication
- `README.md` - This file

## Future Improvements

- Implement actual gRPC-web communication
- Add form validation
- Implement 2FA functionality
- Add OAuth provider login options
- Improve error handling and user feedback