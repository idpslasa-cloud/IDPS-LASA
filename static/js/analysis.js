(function () {
  const ctx = document.getElementById('attack-chart');
  if (!ctx || typeof Chart === 'undefined') return;

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: LABELS,
      datasets: [{
        label: 'Attacks',
        data: VALUES,
        backgroundColor: 'rgba(248, 81, 73, 0.4)',
        borderColor: 'rgba(248, 81, 73, 0.9)',
        borderWidth: 1,
        borderRadius: 4,
        hoverBackgroundColor: 'rgba(248, 81, 73, 0.65)',
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.parsed.y} attack${ctx.parsed.y !== 1 ? 's' : ''}`,
          },
        },
      },
      scales: {
        x: {
          ticks: { color: '#8b949e', font: { size: 11 } },
          grid: { color: 'rgba(48,54,61,0.6)' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#8b949e', precision: 0 },
          grid: { color: 'rgba(48,54,61,0.6)' },
        },
      },
    },
  });
})();
