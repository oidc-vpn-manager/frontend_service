document.addEventListener('DOMContentLoaded', function () {
    const adminRevocationDialog = document.getElementById('adminRevocationDialog');
    const bulkRevocationDialog = document.getElementById('bulkRevocationDialog');

    function showAdminRevocationDialog(fingerprint, subject) {
        document.getElementById('adminRevocationForm').action = `/admin/certificates/${fingerprint}/revoke`;
        adminRevocationDialog.style.display = 'block';
    }

    function hideAdminRevocationDialog() {
        adminRevocationDialog.style.display = 'none';
    }

    function showBulkRevocationDialog(userId, subject) {
        document.getElementById('bulkRevocationForm').action = `/admin/users/${userId}/revoke-certificates`;
        
        // Populate the user input field
        const userInput = document.getElementById('bulkRevocationUser');
        if (userInput) {
            userInput.value = subject || userId || 'Unknown User';
        }
        
        bulkRevocationDialog.style.display = 'block';
    }

    function hideBulkRevocationDialog() {
        bulkRevocationDialog.style.display = 'none';
    }

    // Event listeners for buttons
    const adminRevokeBtn = document.querySelector('.admin-revoke-btn');
    if (adminRevokeBtn) {
        adminRevokeBtn.addEventListener('click', function () {
            const fingerprint = this.dataset.fingerprint;
            const subject = this.dataset.subject;
            showAdminRevocationDialog(fingerprint, subject);
        });
    }

    const bulkRevokeBtn = document.querySelector('.bulk-revoke-btn');
    if (bulkRevokeBtn) {
        bulkRevokeBtn.addEventListener('click', function () {
            const userId = this.dataset.userId;
            const subject = this.dataset.subject;
            showBulkRevocationDialog(userId, subject);
        });
    }

    const cancelAdminRevocationBtn = document.querySelector('[data-testid="cancel-admin-revocation"]');
    if (cancelAdminRevocationBtn) {
        cancelAdminRevocationBtn.addEventListener('click', hideAdminRevocationDialog);
    }

    const cancelBulkRevocationBtn = document.querySelector('[data-testid="cancel-bulk-revocation"]');
    if (cancelBulkRevocationBtn) {
        cancelBulkRevocationBtn.addEventListener('click', hideBulkRevocationDialog);
    }


    // Close dialogs when clicking outside
    window.addEventListener('click', function (event) {
        if (event.target === adminRevocationDialog) {
            hideAdminRevocationDialog();
        }
        if (event.target === bulkRevocationDialog) {
            hideBulkRevocationDialog();
        }
    });
});
