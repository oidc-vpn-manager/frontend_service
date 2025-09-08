document.addEventListener('DOMContentLoaded', function () {
    const commandModal = document.getElementById('commandModal');

    function showCommandModal(description, psk) {
        document.getElementById('modalDescription').textContent = description;
        document.getElementById('cmdDescription').textContent = description;
        document.getElementById('cmdPsk').textContent = psk;
        if (commandModal) {
            commandModal.style.display = 'block';
        }
    }

    function closeCommandModal() {
        if (commandModal) {
            commandModal.style.display = 'none';
        }
    }

    function copyToClipboard(button, text) {
        navigator.clipboard.writeText(text).then(function () {
            button.textContent = 'Copied!';
            button.classList.add('copied');
            setTimeout(function () {
                button.textContent = 'Copy';
                button.classList.remove('copied');
            }, 2000);
        }).catch(function (err) {
            console.error('Failed to copy text: ', err);
            fallbackCopyTextToClipboard(text, button);
        });
    }

    function copyPythonCommand() {
        const description = document.getElementById('cmdDescription').textContent;
        const psk = document.getElementById('cmdPsk').textContent;
        const command = `python3 get_openvpn_config.py --description ${description} --psk ${psk}`;

        const button = event.target;
        copyToClipboard(button, command);
    }

    function fallbackCopyTextToClipboard(text, button) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.top = "0";
        textArea.style.left = "0";
        textArea.style.position = "fixed";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            const successful = document.execCommand('copy');
            if (successful) {
                button.textContent = 'Copied!';
                button.classList.add('copied');
                setTimeout(function () {
                    button.textContent = 'Copy';
                    button.classList.remove('copied');
                }, 2000);
            }
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }

        document.body.removeChild(textArea);
    }

    // Event listeners
    document.querySelectorAll('.revoke-btn').forEach(button => {
        button.addEventListener('click', function (event) {
            if (!confirm('Are you sure you want to revoke this key?')) {
                event.preventDefault();
            }
        });
    });

    const closeBtn = document.querySelector('.modal .close');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeCommandModal);
    }

    document.querySelectorAll('.copy-button').forEach(button => {
        button.addEventListener('click', function() {
            const text = this.dataset.copyText;
            if (text) {
                copyToClipboard(this, text);
            }
        });
    });
    
    const pythonCopyBtn = document.getElementById('copyPythonCommandBtn');
    if(pythonCopyBtn) {
        pythonCopyBtn.addEventListener('click', copyPythonCommand);
    }

    const modalCloseButton = document.querySelector('.modal-footer .button');
    if(modalCloseButton) {
        modalCloseButton.addEventListener('click', closeCommandModal);
    }

    window.addEventListener('click', function (event) {
        if (event.target == commandModal) {
            closeCommandModal();
        }
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            closeCommandModal();
        }
    });
});
