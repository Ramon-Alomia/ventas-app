// static/js/dashboard.js

document.addEventListener('DOMContentLoaded', () => {
  const table = document.getElementById('lines');
  const addBtn = document.getElementById('addLine');
  const whSelect = document.getElementById('warehouse');
  const cardcodeContainer = document.getElementById('cardcode-container');

  let currentItems = [];

  function fillItemSelect(sel) {
    sel.innerHTML = '<option value="" disabled selected>Selecciona un menú…</option>';
    currentItems.forEach(it => {
      const opt = document.createElement('option');
      opt.value = it.itemcode;
      opt.textContent = it.description;
      sel.appendChild(opt);
    });
    sel.disabled = currentItems.length === 0;
  }

  function updateItemSelects() {
    table.querySelectorAll('select[name="item_code"]').forEach(fillItemSelect);
  }

  function loadItems(whscode) {
    fetch(`/warehouses/${encodeURIComponent(whscode)}/items`)
      .then(r => {
        if (!r.ok) throw new Error('No se pudo cargar items');
        return r.json();
      })
      .then(data => {
        currentItems = data;
        updateItemSelects();
      })
      .catch(err => console.error(err));
  }

  function renderCardcode(whscode) {
    const options = warehousesData[whscode] || [];
    cardcodeContainer.innerHTML = '';
    if (options.length > 1) {
      const select = document.createElement('select');
      select.name = 'cardcode';
      select.id = 'cardcode';
      select.required = true;
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.disabled = true;
      placeholder.selected = true;
      placeholder.textContent = 'Selecciona descripción…';
      select.appendChild(placeholder);
      options.forEach(o => {
        const opt = document.createElement('option');
        opt.value = o.cardcode;
        opt.textContent = o.whsdesc;
        select.appendChild(opt);
      });
      cardcodeContainer.appendChild(select);
    } else if (options.length === 1) {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'cardcode';
      input.value = options[0].cardcode;
      cardcodeContainer.appendChild(input);
      const strong = document.createElement('strong');
      strong.textContent = options[0].whsdesc;
      cardcodeContainer.appendChild(strong);
    }
  }

  if (whSelect) {
    whSelect.addEventListener('change', e => {
      const wh = e.target.value;
      renderCardcode(wh);
      loadItems(wh);
    });

    if (whSelect.tagName !== 'SELECT') {
      const wh = whSelect.value;
      renderCardcode(wh);
      loadItems(wh);
    }
  }

  addBtn.addEventListener('click', () => {
    const first = table.querySelector('.line');
    const clone = first.cloneNode(true);
    clone.querySelector('input[name="quantity"]').value = '';
    const sel = clone.querySelector('select[name="item_code"]');
    fillItemSelect(sel);
    table.appendChild(clone);
  });

  table.addEventListener('click', e => {
    if (e.target.classList.contains('remove')) {
      const rows = table.querySelectorAll('.line');
      if (rows.length > 1) {
        e.target.closest('tr').remove();
      }
    }
  });
});

