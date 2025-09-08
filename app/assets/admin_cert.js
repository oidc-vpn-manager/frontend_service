document.addEventListener('DOMContentLoaded', function () {
    const adminRevocationDialog = document.getElementById('adminRevocationDialog');
    const bulkRevocationDialog = document.getElementById('bulkRevocationDialog');

    function showAdminRevocationDialog(fingerprint, subject) {
        console.log('showAdminRevocationDialog called with:', fingerprint, subject);
        var form = document.getElementById('adminRevocationForm');
        var dialog = document.getElementById('adminRevocationDialog');

        if (!form) {
            console.error('adminRevocationForm not found');
            return;
        }

        if (!dialog) {
            console.error('adminRevocationDialog not found');
            return;
        }

        form.action = '/admin/certificates/' + fingerprint + '/revoke';
        dialog.style.display = 'block';
        console.log('Modal should now be visible');
    }

    function hideAdminRevocationDialog() {
        if (adminRevocationDialog) {
            adminRevocationDialog.style.display = 'none';
        }
    }

    function showBulkRevocationDialog() {
        console.log('showBulkRevocationDialog called');
        // Try to determine user_id from the first certificate displayed
        const certificates = document.querySelectorAll('[data-testid="certificate-row"]');
        if (certificates.length === 0) {
            alert('No certificates found. Please apply filters to show certificates for a specific user.');
            return;
        }

        // Look for certificates to determine the target user for bulk revocation
        const subjectFilter = document.getElementById('subject');
        const userInput = document.getElementById('bulkRevocationUser');
        const form = document.getElementById('bulkRevocationForm');
        let userId = null;
        let displayName = '';

        // Check if we're filtering by subject (user clicked filter)
        if (subjectFilter && subjectFilter.value.trim() !== '') {
            const filterValue = subjectFilter.value.trim();
            // Clean the display name by removing timestamp suffix
            displayName = filterValue.replace(/-\d+$/, '');

            // Find certificates matching this subject to get the issuing_user_id
            const matchingCerts = Array.from(certificates).filter(row => {
                const subjectCell = row.querySelector('td strong');
                return subjectCell && subjectCell.textContent.includes(filterValue);
            });

            if (matchingCerts.length > 0) {
                // Extract issuing_user_id directly from the certificate row data attribute
                const certRow = matchingCerts[0];
                userId = certRow.getAttribute('data-issuing-user-id');
            }
        }

        // If we couldn't find user ID from subject filter, look at visible certificates
        if (!userId) {
            // Get the most common issuing_user_id from currently visible certificates
            const userCounts = {};
            Array.from(certificates).forEach(row => {
                const issuingUserId = row.getAttribute('data-issuing-user-id');
                if (issuingUserId && issuingUserId.trim() !== '') {
                    userCounts[issuingUserId] = (userCounts[issuingUserId] || 0) + 1;
                }
            });

            // Find the user ID with the most certificates (bulk target)
            let maxCount = 0;
            for (const [uid, count] of Object.entries(userCounts)) {
                if (count > maxCount) {
                    maxCount = count;
                    userId = uid;
                }
            }

            // Set display name based on the selected user's certificates
            if (userId) {
                const userCertRow = Array.from(certificates).find(row => {
                    return row.getAttribute('data-issuing-user-id') === userId;
                });

                if (userCertRow) {
                    const subjectElement = userCertRow.querySelector('td strong');
                    if (subjectElement) {
                        displayName = subjectElement.textContent.replace(/-\d+$/, '');
                    }
                }
            }
        }

        // Fallback if we still couldn't determine user ID
        if (!userId) {
            alert('Cannot determine target user for bulk revocation. Please filter by a specific user first.');
            return;
        }

        userInput.value = displayName;

        form.action = '/admin/users/' + userId + '/revoke-certificates';
        console.log('Setting bulk revocation form action to:', form.action);
        if (bulkRevocationDialog) {
            bulkRevocationDialog.style.display = 'block';
        }
        console.log('Bulk modal should now be visible');
    }

    function hideBulkRevocationDialog() {
        if (bulkRevocationDialog) {
            bulkRevocationDialog.style.display = 'none';
        }
    }

    // Event listeners for buttons
    document.querySelectorAll('.admin-revoke-btn').forEach(button => {
        button.addEventListener('click', function () {
            const fingerprint = this.dataset.fingerprint;
            const subject = this.dataset.subject;
            showAdminRevocationDialog(fingerprint, subject);
        });
    });

    const bulkRevokeUserBtn = document.querySelector('[data-testid="bulk-revoke-user"]');
    if (bulkRevokeUserBtn) {
        bulkRevokeUserBtn.addEventListener('click', showBulkRevocationDialog);
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
        if (event.target == adminRevocationDialog) {
            hideAdminRevocationDialog();
        }
        if (event.target == bulkRevocationDialog) {
            hideBulkRevocationDialog();
        }
    });
});
