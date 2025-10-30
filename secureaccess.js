// SecureAccess JavaScript File
// Database connection parameters
const DB_CONFIG = {
    host: 'localhost',
    port: 3306,
    database: 'secureaccess2',
    username: 'UserName',
    password: 'PassWord'
};

// Get URL parameters
function getUrlParameter(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

// Initialize page when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get any parameters passed to this webpage
    const receivedParameter = getUrlParameter('param');
    
    // Get form elements
    const txtApplicationName = document.getElementById('txtApplicationName');
    const txtUserAccount = document.getElementById('txtUserAccount');
    const txtPassword = document.getElementById('txtPassword');
    const submitBtn = document.getElementById('submitBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    
    // Handle any received parameters
    if (receivedParameter) {
        console.log('Received parameter:', receivedParameter);
        // Process the parameter as needed
    }
    
    // Submit button event (no functionality added as requested)
    submitBtn.addEventListener('click', function() {
        // Submit button clicked - no code added as requested
    });
    
    // Cancel button event (no functionality added as requested)
    cancelBtn.addEventListener('click', function() {
        // Cancel button clicked - no code added as requested
    });
});

// Function to get form data (utility function for future use)
function getFormData() {
    return {
        userAccount: document.getElementById('txtUserAccount').value,
        password: document.getElementById('txtPassword').value
    };
}