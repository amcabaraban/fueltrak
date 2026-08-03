// ============================================================
// FuelTrak - Global Error Handler
// ============================================================

const ErrorHandler = {
    // Toast notification container
    toastContainer: null,

    // Initialize error handler
    init: function() {
        if (!this.toastContainer) {
            this.toastContainer = document.createElement('div');
            this.toastContainer.id = 'errorToastContainer';
            this.toastContainer.className = 'fixed top-4 right-4 z-[9999] space-y-2 max-w-sm';
            document.body.appendChild(this.toastContainer);
        }
    },

    // Show toast notification
    toast: function(message, type = 'error', duration = 6000) {
        this.init();
        
        const colors = {
            error: 'bg-red-500',
            warning: 'bg-orange-500',
            success: 'bg-green-500',
            info: 'bg-blue-500'
        };

        const icons = {
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            success: 'fa-check-circle',
            info: 'fa-info-circle'
        };

        const toast = document.createElement('div');
        toast.className = `${colors[type] || colors.error} text-white px-4 py-3 rounded-lg shadow-lg flex items-center space-x-3 transform transition-all duration-300 translate-x-full`;
        toast.innerHTML = `
            <i class="fas ${icons[type] || icons.error} text-lg"></i>
            <span class="text-sm flex-1">${message}</span>
            <button onclick="this.parentElement.remove()" class="text-white/80 hover:text-white">
                <i class="fas fa-times"></i>
            </button>
        `;

        this.toastContainer.appendChild(toast);

        // Animate in
        setTimeout(() => {
            toast.classList.remove('translate-x-full');
            toast.classList.add('translate-x-0');
        }, 100);

        // Auto remove
        setTimeout(() => {
            toast.classList.add('translate-x-full');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    // Handle API errors
    handleAPIError: function(error, customMessage = '') {
        console.error('API Error:', error);

        if (error.name === 'AbortError') {
            this.toast('Request timed out. Please check your connection and try again.', 'warning');
            return;
        }

        if (error.name === 'TypeError' && error.message.includes('NetworkError')) {
            this.toast('Network connection lost. Please check your internet connection.', 'error');
            return;
        }

        if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
            this.toast('Unable to connect to server. Please try again later.', 'error');
            return;
        }

        this.toast(customMessage || 'An unexpected error occurred. Please try again.', 'error');
    },

    // Handle API response errors
    handleAPIResponse: function(response, context = '') {
        if (!response) {
            this.toast('No response from server. Please try again.', 'error');
            return false;
        }

        if (response.status === 401) {
            this.toast('Your session has expired. Please login again.', 'warning');
            setTimeout(() => {
                localStorage.clear();
                window.location.href = '/';
            }, 2000);
            return false;
        }

        if (response.status === 403) {
            this.toast('You do not have permission to perform this action.', 'error');
            return false;
        }

        if (response.status === 429) {
            this.toast('Too many requests. Please wait and try again.', 'warning');
            return false;
        }

        if (response.status >= 500) {
            this.toast('Server error. Our team has been notified. Please try again later.', 'error');
            return false;
        }

        if (response.error) {
            this.toast(response.error, 'error');
            return false;
        }

        return true;
    },

    // Handle validation errors
    handleValidationError: function(errors) {
        if (typeof errors === 'string') {
            this.toast(errors, 'warning');
        } else if (Array.isArray(errors)) {
            errors.forEach(err => this.toast(err, 'warning'));
        }
    },

    // Handle form submission errors
    handleFormError: function(formElement, message) {
        this.toast(message, 'error');
        
        // Shake the form to draw attention
        if (formElement) {
            formElement.classList.add('animate-shake');
            setTimeout(() => formElement.classList.remove('animate-shake'), 500);
        }
    },

    // Show inline field error
    showFieldError: function(fieldId, message) {
        const field = document.getElementById(fieldId);
        if (!field) return;

        field.classList.add('border-red-500', 'bg-red-50');
        
        // Remove existing error message
        const existing = field.parentElement.querySelector('.field-error');
        if (existing) existing.remove();

        // Add error message
        const errorSpan = document.createElement('span');
        errorSpan.className = 'field-error text-red-500 text-xs mt-1 block';
        errorSpan.textContent = message;
        field.parentElement.appendChild(errorSpan);

        // Clear after 5 seconds
        setTimeout(() => {
            field.classList.remove('border-red-500', 'bg-red-50');
            if (errorSpan.parentElement) errorSpan.remove();
        }, 5000);
    },

    // Clear all field errors
    clearFieldErrors: function(formElement) {
        if (!formElement) return;
        formElement.querySelectorAll('.border-red-500').forEach(field => {
            field.classList.remove('border-red-500', 'bg-red-50');
        });
        formElement.querySelectorAll('.field-error').forEach(err => err.remove());
    },

    // Confirm dangerous action
    confirmDanger: function(message, callback) {
        if (confirm(message)) {
            if (confirm('Are you absolutely sure? This action cannot be undone.')) {
                callback();
            }
        }
    },

    // Show loading state on button
    showLoading: function(buttonId, text = 'Processing...') {
        const btn = document.getElementById(buttonId);
        if (!btn) return;
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = `<i class="fas fa-spinner fa-spin mr-2"></i>${text}`;
    },

    // Hide loading state on button
    hideLoading: function(buttonId) {
        const btn = document.getElementById(buttonId);
        if (!btn || !btn.dataset.originalText) return;
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalText;
        delete btn.dataset.originalText;
    },

    // Show skeleton loading
    showSkeleton: function(containerId, count = 3) {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = Array(count).fill(0).map(() => `
            <div class="bg-gray-200 animate-pulse rounded-xl p-6">
                <div class="h-4 bg-gray-300 rounded w-3/4 mb-3"></div>
                <div class="h-3 bg-gray-300 rounded w-1/2 mb-2"></div>
                <div class="h-3 bg-gray-300 rounded w-2/3"></div>
            </div>
        `).join('');
    },

    // Show empty state
    showEmpty: function(containerId, message = 'No data available', icon = 'fa-inbox') {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = `
            <div class="text-center py-12 text-gray-400">
                <i class="fas ${icon} text-4xl mb-3 block"></i>
                <p class="text-lg">${message}</p>
            </div>
        `;
    },

    // Show error state
    showError: function(containerId, message = 'Failed to load data', retryFn = null) {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = `
            <div class="text-center py-12 text-red-400">
                <i class="fas fa-exclamation-circle text-4xl mb-3 block"></i>
                <p class="text-lg">${message}</p>
                ${retryFn ? '<button onclick="(' + retryFn.toString() + ')()" class="mt-3 text-blue-600 hover:underline text-sm">Try Again</button>' : ''}
            </div>
        `;
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => ErrorHandler.init());

// Global error handlers
window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
    ErrorHandler.toast('An unexpected error occurred. Please refresh the page.', 'error');
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
    if (e.reason && e.reason.name !== 'AbortError') {
        ErrorHandler.toast('Connection issue detected. Please check your network.', 'warning');
    }
});