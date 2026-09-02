(function () {
    const container = document.getElementById("events-over-time-chart");

    if (!container) {
        return;
    }

    let events = [];

    try {
        events = JSON.parse(container.dataset.events || "[]");
    } catch (error) {
        events = [];
    }

    const width = 760;
    const height = 274;
    const padding = { top: 24, right: 28, bottom: 36, left: 42 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;
    const maxCount = Math.max(1, ...events.map((item) => Number(item.count) || 0));
    const points = events.map((item, index) => {
        const x = padding.left + (events.length === 1 ? chartWidth / 2 : (index / (events.length - 1)) * chartWidth);
        const y = padding.top + chartHeight - ((Number(item.count) || 0) / maxCount) * chartHeight;
        return { x, y, count: item.count, hour: item.hour };
    });

    const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {
        const y = padding.top + chartHeight * ratio;
        return `<line class="chart-grid" x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}"></line>`;
    }).join("");

    const linePath = points.map((point, index) => {
        const command = index === 0 ? "M" : "L";
        return `${command}${point.x},${point.y}`;
    }).join(" ");

    const areaPath = points.length
        ? `${linePath} L${points[points.length - 1].x},${padding.top + chartHeight} L${points[0].x},${padding.top + chartHeight} Z`
        : "";

    const circles = points.map((point) => (
        `<circle cx="${point.x}" cy="${point.y}" r="4"><title>${point.hour}: ${point.count}</title></circle>`
    )).join("");

    const firstLabel = points[0] ? points[0].hour.slice(11, 16) : "No data";
    const lastLabel = points.length > 1 ? points[points.length - 1].hour.slice(11, 16) : firstLabel;

    container.innerHTML = `
        <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Security events over the last 24 hours">
            ${gridLines}
            ${areaPath ? `<path class="chart-area-fill" d="${areaPath}"></path>` : ""}
            ${linePath ? `<path class="chart-line" d="${linePath}"></path>` : ""}
            ${circles}
            <text class="chart-label" x="${padding.left}" y="${height - 12}">${firstLabel}</text>
            <text class="chart-label" x="${width - padding.right - 34}" y="${height - 12}">${lastLabel}</text>
            <text class="chart-label" x="12" y="${padding.top + 8}">${maxCount}</text>
            <text class="chart-label" x="18" y="${padding.top + chartHeight}">0</text>
        </svg>
    `;
}());
