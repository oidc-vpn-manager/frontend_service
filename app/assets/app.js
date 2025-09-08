/**
 * A utility function to copy text to the clipboard and provide user feedback.
 */
function copyToClipboard(button, text) {
    navigator.clipboard.writeText(text).then(() => {
        // Provide feedback to the user
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.disabled = true;
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000); // Revert back after 2 seconds
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

// This function runs once the whole page has loaded
document.addEventListener('DOMContentLoaded', () => {
    // Find all elements with the class 'copy-button'
    const copyButtons = document.querySelectorAll('.copy-button');

    // Add a click event listener to each button
    copyButtons.forEach(button => {
        button.addEventListener('click', (event) => {
            // Get the target ID from the button's data-target-id attribute
            const targetId = event.currentTarget.dataset.targetId;
            const commandElement = document.getElementById(targetId);

            if (commandElement) {
                const commandText = commandElement.textContent.trim();
                copyToClipboard(button, commandText);
            }
        });
    });
});