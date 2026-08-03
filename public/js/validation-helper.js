// ============================================================
// FuelTrak - Form Validation Helper
// ============================================================

const ValidationHelper = {
    rules: {
        required: function(value) {
            return value && value.toString().trim().length > 0 ? true : 'This field is required';
        },
        email: function(value) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? true : 'Please enter a valid email address';
        },
        mobile: function(value) {
            return /^(09\d{9}|\+639\d{9})$/.test(value) ? true : 'Enter valid PH mobile (09XXXXXXXXX or +639XXXXXXXXX)';
        },
        minLength: function(min) {
            return function(value) {
                return value && value.length >= min ? true : `Must be at least ${min} characters`;
            };
        },
        maxLength: function(max) {
            return function(value) {
                return value && value.length <= max ? true : `Must be ${max} characters or less`;
            };
        },
        plateNumber: function(value) {
            return value && value.trim().length >= 2 ? true : 'Please enter a valid plate number';
        },
        volume: function(value) {
            const v = parseFloat(value);
            if (isNaN(v) || v <= 0) return 'Volume must be greater than 0';
            if (v > 100000) return 'Volume cannot exceed 100,000 liters';
            return true;
        },
        password: function(value) {
            if (!value || value.length < 8) return 'Password must be at least 8 characters';
            if (!/[A-Z]/.test(value)) return 'Password must contain an uppercase letter';
            if (!/[a-z]/.test(value)) return 'Password must contain a lowercase letter';
            if (!/[0-9]/.test(value)) return 'Password must contain a number';
            if (!/[!@#$%^&*]/.test(value)) return 'Password must contain a special character';
            return true;
        },
        passwordMatch: function(matchFieldId) {
            return function(value) {
                const matchValue = document.getElementById(matchFieldId)?.value;
                return value === matchValue ? true : 'Passwords do not match';
            };
        }
    },

    // Validate a single field
    validateField: function(fieldId, rule) {
        const field = document.getElementById(fieldId);
        if (!field) return true;

        const value = field.value;
        let result;

        if (typeof rule === 'function') {
            result = rule(value);
        } else if (typeof rule === 'string' && this.rules[rule]) {
            result = this.rules[rule](value);
        }

        if (result === true) {
            ErrorHandler.showFieldError(fieldId, '');
            field.classList.remove('border-red-500', 'bg-red-50');
            field.classList.add('border-green-500');
            return true;
        } else {
            ErrorHandler.showFieldError(fieldId, result);
            return false;
        }
    },

    // Validate entire form
    validateForm: function(formId, fieldRules) {
        const form = document.getElementById(formId);
        if (!form) return false;

        ErrorHandler.clearFieldErrors(form);
        let isValid = true;

        for (const [fieldId, rule] of Object.entries(fieldRules)) {
            if (!this.validateField(fieldId, rule)) {
                isValid = false;
            }
        }

        if (!isValid) {
            ErrorHandler.toast('Please fix the highlighted fields before submitting.', 'warning');
        }

        return isValid;
    },

    // Validate ATL submission form
    validateATLForm: function() {
        const rules = {
            'company': 'required',
            'soNumber': 'required',
            'plateNo': 'plateNumber',
            'volume': 'volume',
            'driverName': 'required',
            'hauler': 'required',
            'contactNumber': 'mobile',
            'scheduledDate': 'required'
        };

        if (!this.validateForm('atlForm', rules)) return false;

        // Additional check for truck verification
        if (typeof truckVerified !== 'undefined' && !truckVerified) {
            ErrorHandler.toast('Please verify the truck plate number first.', 'warning');
            return false;
        }

        return true;
    },

    // Real-time field validation on input
    bindRealTimeValidation: function(fieldId, rule) {
        const field = document.getElementById(fieldId);
        if (!field) return;

        field.addEventListener('input', () => {
            if (field.value.length > 0) {
                this.validateField(fieldId, rule);
            }
        });

        field.addEventListener('blur', () => {
            this.validateField(fieldId, rule);
        });
    }
};