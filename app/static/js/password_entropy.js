function calculateEntropy(password) {
    const asciiLower = 'abcdefghijklmnopqrstuvwxyz';
    const asciiUpper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const specialChars = '!@#$%^&*()_+[]{}|;:,.<>?';
    let poolSize = 0;

    if (/[a-z]/.test(password)) poolSize += asciiLower.length;
    if (/[A-Z]/.test(password)) poolSize += asciiUpper.length;
    if (/\d/.test(password)) poolSize += digits.length;
    if (/[\W_]/.test(password)) poolSize += specialChars.length;

    if (poolSize === 0) return 0;

    return Math.log2(poolSize) * password.length;
}

function validatePasswordStrength(inputId, feedbackId, submitId) {
    const passwordInput = document.getElementById(inputId);
    const feedback = document.getElementById(feedbackId);
    const submitButton = document.getElementById(submitId);

    if (passwordInput && feedback && submitButton) {
        passwordInput.addEventListener('input', () => {
            const password = passwordInput.value;
            const entropy = calculateEntropy(password);

            if (entropy < 30) {
                feedback.textContent = "Password strength: Very weak";
                submitButton.disabled = true;
            } else if (entropy < 50) {
                feedback.textContent = "Password strength: Weak";
                submitButton.disabled = true;
            } else if (entropy < 60) {
                feedback.textContent = "Password strength: Moderate";
                submitButton.disabled = true;
            } else {
                feedback.textContent = "Password strength: Strong";
                submitButton.disabled = false;
            }
        });
    } else {
        // nic sie nie dzieje jesli nie ma pol
    }
}

document.addEventListener('DOMContentLoaded', () => {
    validatePasswordStrength('password', 'passwordFeedback', 'submitButton');
    validatePasswordStrength('new_password', 'newPasswordFeedback', 'submitButton');
});
