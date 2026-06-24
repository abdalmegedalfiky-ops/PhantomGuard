/* Dashboard filtering: severity chip-filter + decision chip-filter + free-text search.
   كل البيانات موجودة في data-* attributes على كل alert-row، فمفيش حاجة بتتبعت للسيرفر. */
(function () {
  const list = document.getElementById('alertList');
  if (!list) return;

  const rows = Array.from(list.querySelectorAll('.alert-row'));
  const searchInput = document.getElementById('searchInput');
  const noResults = document.getElementById('noResults');
  const state = { severity: 'all', decision: 'all', query: '' };

  function apply() {
    let visibleCount = 0;
    rows.forEach((row) => {
      const sevOk = state.severity === 'all' || row.dataset.severity === state.severity;
      const decOk = state.decision === 'all' || row.dataset.decision === state.decision;
      const searchOk = !state.query || row.dataset.search.includes(state.query);
      const visible = sevOk && decOk && searchOk;
      row.style.display = visible ? '' : 'none';
      if (visible) visibleCount += 1;
    });
    if (noResults) noResults.style.display = visibleCount === 0 ? '' : 'none';
  }

  document.querySelectorAll('[data-filter-group]').forEach((group) => {
    const key = group.dataset.filterGroup;
    group.querySelectorAll('.chip-filter').forEach((btn) => {
      btn.addEventListener('click', () => {
        group.querySelectorAll('.chip-filter').forEach((b) => b.classList.remove('is-active'));
        btn.classList.add('is-active');
        state[key] = btn.dataset.value;
        apply();
      });
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.query = e.target.value.trim().toLowerCase();
      apply();
    });
  }
})();
