// DOM Elements
const loginSection = document.getElementById('loginSection');
const registerSection = document.getElementById('registerSection');
const resetSection = document.getElementById('resetSection');
const profileSection = document.getElementById('profileSection');

const loginBtn = document.getElementById('loginBtn');
const registerBtn = document.getElementById('registerBtn');
const resetBtn = document.getElementById('resetBtn');
const profileBtn = document.getElementById('profileBtn');

const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const resetForm = document.getElementById('resetForm');
const newPasswordForm = document.getElementById('newPasswordForm');
const updateProfileForm = document.getElementById('updateProfileForm');

// Message elements
const loginMessage = document.getElementById('loginMessage');
const registerMessage = document.getElementById('registerMessage');
const resetMessage = document.getElementById('resetMessage');
const newPasswordMessage = document.getElementById('newPasswordMessage');
const profileMessage = document.getElementById('profileMessage');
const profileInfo = document.getElementById('profileInfo');

// Auth state
let authToken = localStorage.getItem('authToken') || null;
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// Navigation functions
function showSection(section) {
    // Hide all sections
    loginSection.classList.remove('active');
    registerSection.classList.remove('active');
    resetSection.classList.remove('active');
    profileSection.classList.remove('active');
    
    // Deactivate all buttons
    loginBtn.classList.remove('active');
    registerBtn.classList.remove('active');
    resetBtn.classList.remove('active');
    profileBtn.classList.remove('active');
    
    // Show selected section
    section.classList.add('active');
}

// Button event listeners
loginBtn.addEventListener('click', () => {
    showSection(loginSection);
    loginBtn.classList.add('active');
});

registerBtn.addEventListener('click', () => {
    showSection(registerSection);
    registerBtn.classList.add('active');
});

resetBtn.addEventListener('click', () => {
    showSection(resetSection);
    resetBtn.classList.add('active');
});

profileBtn.addEventListener('click', () => {
    showSection(profileSection);
    profileBtn.classList.add('active');
    if (authToken) {
        displayProfile();
    }
});

// Form submission handlers
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const login = document.getElementById('login').value;
    const password = document.getElementById('loginPassword').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    try {
        const response = await loginRequest(login, password, rememberMe);
        showMessage(loginMessage, response.message, 'success');
        
        // Store token and user data
        authToken = response.accessToken;
        currentUser = response.user;
        localStorage.setItem('authToken', authToken);
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        
        // Update profile section
        displayProfile();
        showSection(profileSection);
        profileBtn.classList.add('active');
    } catch (error) {
        showMessage(loginMessage, error.message, 'error');
    }
});

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fullName = document.getElementById('fullName').value;
    const email = document.getElementById('regEmail').value;
    const phone = document.getElementById('regPhone').value;
    const password = document.getElementById('regPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const acceptTerms = document.getElementById('acceptTerms').checked;
    
    try {
        const response = await registerRequest(fullName, email, phone, password, confirmPassword, acceptTerms);
        showMessage(registerMessage, response.message, 'success');
        
        // If registration requires verification, show message
        if (response.requiresVerification) {
            showMessage(registerMessage, 
                `${response.message} Please check your ${response.verificationType} for verification code.`, 
                'info');
        }
        
        // Clear form
        registerForm.reset();
        
        // Switch to login form
        showSection(loginSection);
        loginBtn.classList.add('active');
    } catch (error) {
        showMessage(registerMessage, error.message, 'error');
    }
});

resetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('resetEmail').value;
    
    try {
        const response = await requestPasswordReset(email);
        showMessage(resetMessage, response.message, 'success');
        
        // Show the new password form
        document.getElementById('resetForm').style.display = 'none';
        newPasswordForm.style.display = 'block';
    } catch (error) {
        showMessage(resetMessage, error.message, 'error');
    }
});

newPasswordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const resetToken = document.getElementById('resetToken').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmNewPassword = document.getElementById('confirmNewPassword').value;
    
    try {
        const response = await resetPassword(resetToken, newPassword, confirmNewPassword);
        showMessage(newPasswordMessage, response.message, 'success');
        
        // Hide the new password form and show the reset form
        newPasswordForm.style.display = 'none';
        document.getElementById('resetForm').style.display = 'block';
        newPasswordForm.reset();
    } catch (error) {
        showMessage(newPasswordMessage, error.message, 'error');
    }
});

updateProfileForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fullName = document.getElementById('profileFullName').value;
    const phone = document.getElementById('profilePhone').value;
    
    try {
        const response = await updateProfile(fullName, phone);
        showMessage(profileMessage, response.message, 'success');
        
        // Update current user data
        currentUser = response.user;
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        
        // Update profile display
        displayProfile();
    } catch (error) {
        showMessage(profileMessage, error.message, 'error');
    }
});

// Display user profile
function displayProfile() {
    if (currentUser) {
        profileInfo.innerHTML = `
            <div class="profile-item"><strong>ID:</strong> ${currentUser.id}</div>
            <div class="profile-item"><strong>Name:</strong> ${currentUser.fullName}</div>
            <div class="profile-item"><strong>Email:</strong> ${currentUser.email}</div>
            <div class="profile-item"><strong>Phone:</strong> ${currentUser.phone || 'Not provided'}</div>
            <div class="profile-item"><strong>Role:</strong> ${currentUser.role}</div>
            <div class="profile-item"><strong>Email Verified:</strong> ${currentUser.isEmailVerified ? 'Yes' : 'No'}</div>
            <div class="profile-item"><strong>Phone Verified:</strong> ${currentUser.isPhoneVerified ? 'Yes' : 'No'}</div>
            <div class="profile-item"><strong>2FA Enabled:</strong> ${currentUser.twoFactorEnabled ? 'Yes' : 'No'}</div>
            <div class="profile-item"><strong>Provider:</strong> ${currentUser.provider}</div>
            <div class="profile-item"><strong>Created At:</strong> ${currentUser.createdAt}</div>
            <div class="profile-item"><strong>Last Login:</strong> ${currentUser.lastLoginAt || 'Never'}</div>
        `;
        updateProfileForm.style.display = 'block';
        
        // Populate form with current data
        document.getElementById('profileFullName').value = currentUser.fullName;
        document.getElementById('profilePhone').value = currentUser.phone || '';
    } else {
        profileInfo.innerHTML = '<p>Please login to view your profile.</p>';
        updateProfileForm.style.display = 'none';
    }
}

// Message display function
function showMessage(element, message, type) {
    element.textContent = message;
    element.className = `message ${type}`;
    
    // Clear message after 5 seconds
    setTimeout(() => {
        element.textContent = '';
        element.className = 'message';
    }, 5000);
}

// Simulated API functions (in a real implementation, these would make actual gRPC-web calls)
async function loginRequest(login, password, rememberMe) {
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // This is a mock implementation - in a real app, this would call the gRPC service
    console.log('Login request:', { login, password, rememberMe });
    
    // For demo purposes, return a successful response
    return {
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        accessExpiresIn: 900,
        refreshExpiresIn: 86400,
        user: {
            id: '1',
            fullName: 'Test User',
            email: 'test@example.com',
            phone: '',
            role: 'user',
            isEmailVerified: true,
            isPhoneVerified: false,
            twoFactorEnabled: false,
            provider: 'local',
            lastLoginAt: new Date().toISOString(),
            createdAt: new Date().toISOString()
        },
        message: 'Login successful'
    };
}

async function registerRequest(fullName, email, phone, password, confirmPassword, acceptTerms) {
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log('Register request:', { fullName, email, phone, password, confirmPassword, acceptTerms });
    
    // For demo purposes, return a successful response
    return {
        userId: '1',
        message: 'Registration successful',
        requiresVerification: true,
        verificationType: 'email'
    };
}

async function requestPasswordReset(email) {
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log('Password reset request:', { email });
    
    // For demo purposes, return a successful response
    return {
        message: 'If the email exists, a password reset link has been sent'
    };
}

async function resetPassword(resetToken, newPassword, confirmPassword) {
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log('Reset password request:', { resetToken, newPassword, confirmPassword });
    
    // For demo purposes, return a successful response
    return {
        message: 'Password has been reset successfully',
        success: true
    };
}

async function updateProfile(fullName, phone) {
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log('Update profile request:', { fullName, phone });
    
    // For demo purposes, return a successful response
    return {
        user: {
            id: '1',
            fullName: fullName,
            email: 'test@example.com',
            phone: phone,
            role: 'user',
            isEmailVerified: true,
            isPhoneVerified: false,
            twoFactorEnabled: false,
            provider: 'local',
            lastLoginAt: new Date().toISOString(),
            createdAt: new Date().toISOString()
        },
        message: 'Profile updated successfully'
    };
}

// Initialize the page
document.addEventListener('DOMContentLoaded', () => {
    // Show login section by default
    showSection(loginSection);
    loginBtn.classList.add('active');
    
    // If user is already logged in, display profile
    if (authToken && currentUser) {
        displayProfile();
    }
});