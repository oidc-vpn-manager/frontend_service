document.addEventListener('DOMContentLoaded', function () {
    const pskTypeSelect = document.getElementById('psk_type_select');
    if (!pskTypeSelect) {
        return;
    }

    const conditionalGroups = document.querySelectorAll('[data-psk-type]');

    function syncVisibility() {
        const selected = pskTypeSelect.value;
        conditionalGroups.forEach(function (group) {
            const target = group.dataset.pskType;
            const isVisible = target === selected;
            group.style.display = isVisible ? '' : 'none';
            const inputs = group.querySelectorAll('select, input');
            inputs.forEach(function (input) {
                input.disabled = !isVisible;
            });
        });
    }

    pskTypeSelect.addEventListener('change', syncVisibility);
    syncVisibility();
});
