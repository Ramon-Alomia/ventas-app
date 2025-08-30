// static/js/dashboard.js

document.addEventListener('DOMContentLoaded', () => {
  const table = document.getElementById('lines');
  const addBtn = document.getElementById('addLine');
  const whSelect = document.getElementById('warehouse');
  const cardcodeContainer = document.getElementById('cardcode-container');

  let currentItems = [];

  // Obtener datos de almacenes del script JSON embebido
  const warehousesDataElement = document.getElementById('warehouses-json');
  const warehousesData = warehousesDataElement ? JSON.parse(warehousesDataElement.textContent) : {};

  function fillItemSelect(sel) {
    sel.innerHTML = '<option value="" disabled selected>Selecciona un menú…</option>';
    currentItems.forEach(it => {
      const opt = document.createElement('option');
      opt.value = it.itemcode;
      opt.textContent = it.description;
      sel.appendChild(opt);
    });
    if (currentItems.length > 0) {
      sel.removeAttribute('disabled');
    } else {
      sel.disabled = true;
    }
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
      // Crear select de CardCode si hay múltiples opciones
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
      // Si solo hay una opción, ponerla como valor fijo
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
    const handleWhChange = () => {
      const wh = whSelect.value;
      if (wh) {
        renderCardcode(wh);
        loadItems(wh);
      } else {
        // Si no hay almacén seleccionado, limpiar items y cardcode
        currentItems = [];
        updateItemSelects();
        cardcodeContainer.innerHTML = '';
      }
    };
    whSelect.addEventListener('change', handleWhChange);
    // Cargar items iniciales si el almacén ya está preseleccionado
    handleWhChange();
  }

  addBtn.addEventListener('click', () => {
    const first = table.querySelector('.line');
    const clone = first.cloneNode(true);
    // Limpiar el valor de cantidad en la nueva línea
    clone.querySelector('input[name="quantity"]').value = '';
    // Preparar el select de ítems de la nueva línea con los ítems actuales
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

  // Eventos para mensajes de validación personalizados (sin atributos inline)
  document.addEventListener('invalid', (e) => {
    if (e.target.matches('input[name="quantity"]')) {
      e.target.setCustomValidity('Introduce una cantidad mayor a cero');
    }
  }, true);
  document.addEventListener('input', (e) => {
    if (e.target.matches('input[name="quantity"]')) {
      e.target.setCustomValidity('');
    }
  });
});
