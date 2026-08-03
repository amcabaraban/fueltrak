// ============================================================
// FuelTrak - API Helper with Error Handling
// ============================================================

const APIHelper = {
    baseURL: '/api',
    token: null,
    user: null,

    init: function() {
        this.token = localStorage.getItem('fueltrak_token');
        this.user = JSON.parse(localStorage.getItem('fueltrak_user') || '{}');
        
        if (!this.token || !this.user.role) {
            ErrorHandler.toast('Please login to continue.', 'warning');
            setTimeout(() => window.location.href = '/', 2000);
            return false;
        }
        return true;
    },

    getHeaders: function() {
        return {
            'Authorization': 'Bearer ' + this.token,
            'Content-Type': 'application/json'
        };
    },

    // Main API call with timeout and retry
    call: async function(url, method = 'GET', body = null, options = {}) {
        const {
            timeout = 15000,      // 15 seconds default
            retries = 1,          // Retry once on failure
            showToast = true,     // Show error toast
            silent = false        // Don't show any errors
        } = options;

        let lastError = null;

        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), timeout);

                const fetchOptions = {
                    method,
                    headers: this.getHeaders(),
                    signal: controller.signal
                };

                if (body && method !== 'GET') {
                    fetchOptions.body = JSON.stringify(body);
                }

                const response = await fetch(this.baseURL + url, fetchOptions);
                clearTimeout(timeoutId);

                // Handle HTTP errors
                if (response.status === 401) {
                    if (!silent && showToast) {
                        ErrorHandler.toast('Session expired. Redirecting to login...', 'warning');
                    }
                    localStorage.clear();
                    setTimeout(() => window.location.href = '/', 1500);
                    throw new Error('Unauthorized');
                }

                if (response.status === 403) {
                    if (!silent && showToast) {
                        ErrorHandler.toast('Access denied. You don\'t have permission.', 'error');
                    }
                    throw new Error('Forbidden');
                }

                if (response.status === 429) {
                    const retryAfter = response.headers.get('Retry-After') || 60;
                    if (!silent && showToast) {
                        ErrorHandler.toast(`Rate limited. Please wait ${retryAfter} seconds.`, 'warning');
                    }
                    throw new Error('Rate limited');
                }

                if (response.status >= 500) {
                    if (attempt < retries) {
                        // Wait before retry
                        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
                        continue;
                    }
                    if (!silent && showToast) {
                        ErrorHandler.toast('Server error. Please try again later.', 'error');
                    }
                    throw new Error('Server error');
                }

                const data = await response.json();

                // Handle API-level errors
                if (data.status === 'error' || data.error) {
                    if (!silent && showToast) {
                        ErrorHandler.toast(data.error || data.message || 'Request failed', 'error');
                    }
                    return { ...data, _error: true };
                }

                return data;

            } catch (error) {
                lastError = error;
                
                if (error.name === 'AbortError') {
                    if (!silent && showToast) {
                        ErrorHandler.toast('Request timed out. Please try again.', 'warning');
                    }
                    break; // Don't retry on timeout
                }

                if (error.message === 'Unauthorized' || error.message === 'Forbidden') {
                    break; // Don't retry auth errors
                }

                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
                    continue;
                }

                if (!silent && showToast && error.message !== 'Unauthorized' && error.message !== 'Forbidden') {
                    ErrorHandler.toast('Network error. Please check your connection.', 'error');
                }
            }
        }

        return { status: 'error', error: lastError?.message || 'Request failed', _error: true };
    },

    // Shorthand methods
    get: function(url, options = {}) {
        return this.call(url, 'GET', null, options);
    },

    post: function(url, body, options = {}) {
        return this.call(url, 'POST', body, options);
    },

    put: function(url, body, options = {}) {
        return this.call(url, 'PUT', body, options);
    },

    patch: function(url, body, options = {}) {
        return this.call(url, 'PATCH', body, options);
    },

    delete: function(url, options = {}) {
        return this.call(url, 'DELETE', null, options);
    },

    // Upload file
    upload: async function(url, file, options = {}) {
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(this.baseURL + url, {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + this.token },
                body: formData
            });

            if (!response.ok) {
                const data = await response.json();
                ErrorHandler.toast(data.error || 'Upload failed', 'error');
                return { status: 'error', error: data.error, _error: true };
            }

            return await response.json();
        } catch (error) {
            ErrorHandler.handleAPIError(error, 'File upload failed');
            return { status: 'error', error: error.message, _error: true };
        }
    },

    // Download file
    download: async function(url, filename) {
        try {
            const response = await fetch(this.baseURL + url, {
                headers: { 'Authorization': 'Bearer ' + this.token }
            });

            if (!response.ok) throw new Error('Download failed');

            const blob = await response.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(downloadUrl);
            a.remove();
            
            return { status: 'success' };
        } catch (error) {
            ErrorHandler.toast('Download failed. Please try again.', 'error');
            return { status: 'error', error: error.message, _error: true };
        }
    }
};