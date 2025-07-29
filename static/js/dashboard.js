// static/js/dashboard.js

document.addEventListener('DOMContentLoaded', () => {
  const table  = document.getElementById('lines');
  const addBtn = document.getElementById('addLine');

  // Clonar línea
  addBtn.addEventListener('click', () => {
    const first = table.querySelector('.line');
    const clone = first.cloneNode(true);
    clone.querySelector('input[name="quantity"]').value = '';
    clone.querySelector('select[name="item_code"]').selectedIndex = 0;
    table.appendChild(clone);
  });

  // Eliminar línea (dejando al menos una)
  table.addEventListener('click', e => {
    if (e.target.classList.contains('remove')) {
      const rows = table.querySelectorAll('.line');
      if (rows.length > 1) {
        e.target.closest('tr').remove();
      }
    }
  });
});
