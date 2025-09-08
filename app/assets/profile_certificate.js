document.addEventListener('DOMContentLoaded', function () {
    const userRevocationDialog = document.getElementById('userRevocationDialog');

    function showUserRevocationDialog(fingerprint, subject) {
        if (userRevocationDialog) {
            document.getElementById('userRevocationForm').action = `/profile/certificates/${fingerprint}/revoke`;
            userRevocationDialog.style.display = 'block';
        }
    }

    function hideUserRevocationDialog() {
        if (userRevocationDialog) {
            userRevocationDialog.style.display = 'none';
        }
    }

    document.querySelectorAll('[data-testid="revoke-certificate"]').forEach(button => {
        button.addEventListener('click', function () {
            const fingerprint = this.dataset.fingerprint;
            const subject = this.dataset.subject;
            showUserRevocationDialog(fingerprint, subject);
        });
    });

    const cancelBtn = document.querySelector('[data-testid="cancel-revocation"]');
    if(cancelBtn) {
        cancelBtn.addEventListener('click', hideUserRevocationDialog);
    }

    window.addEventListener('click', function (event) {
        if (event.target == userRevocationDialog) {
            hideUserRevocationDialog();
        }
    });
});
