const apiBase = window.MCP_API_BASE || "/api";
const eventsBody = document.getElementById("events-body");
const totalEvents = document.getElementById("total-events");
const latestSource = document.getElementById("latest-source");
const lastEvent = document.getElementById("last-event");
const refreshBtn = document.getElementById("refresh");
const toggleAuto = document.getElementById("toggle-auto");
const limitInput = document.getElementById("limit");

let autoRefresh = true;
let intervalId = null;

function formatPayload(payload) {
  try {
    return JSON.stringify(payload, null, 2);
  } catch (err) {
    return String(payload);
  }
}

function renderEmpty(message) {
  eventsBody.textContent = "";
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "empty";
  cell.textContent = message;
  row.appendChild(cell);
  eventsBody.appendChild(row);
}

async function fetchJSON(path) {
  const headers = {};
  if (window.MCP_API_KEY) {
    headers["x-api-key"] = window.MCP_API_KEY;
  }
  const response = await fetch(`${apiBase}${path}`, { headers });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

async function refresh() {
  const limit = Number(limitInput.value || 50);
  try {
    const [eventsData, statsData] = await Promise.all([
      fetchJSON(`/events?limit=${limit}`),
      fetchJSON("/stats"),
    ]);

    const events = eventsData.events || [];
    totalEvents.textContent = statsData.events_total ?? 0;

    if (events.length > 0) {
      latestSource.textContent = events[0].source || "-";
      lastEvent.textContent = events[0].event_type || "-";
    } else {
      latestSource.textContent = "-";
      lastEvent.textContent = "-";
    }

    if (events.length === 0) {
      renderEmpty("No data yet.");
      return;
    }

    eventsBody.textContent = "";
    const fragment = document.createDocumentFragment();
    events.forEach((event) => {
      const row = document.createElement("tr");

      const timestampCell = document.createElement("td");
      timestampCell.textContent = new Date(event.timestamp).toLocaleString();
      row.appendChild(timestampCell);

      const sourceCell = document.createElement("td");
      sourceCell.textContent = event.source || "-";
      row.appendChild(sourceCell);

      const typeCell = document.createElement("td");
      typeCell.textContent = event.event_type || "-";
      row.appendChild(typeCell);

      const payloadCell = document.createElement("td");
      const payloadPre = document.createElement("pre");
      payloadPre.textContent = formatPayload(event.payload);
      payloadCell.appendChild(payloadPre);
      row.appendChild(payloadCell);

      fragment.appendChild(row);
    });
    eventsBody.appendChild(fragment);
  } catch (err) {
    renderEmpty("Unable to load events.");
  }
}

function schedule() {
  if (intervalId) {
    clearInterval(intervalId);
  }
  if (autoRefresh) {
    intervalId = setInterval(refresh, 5000);
  }
}

refreshBtn.addEventListener("click", refresh);

toggleAuto.addEventListener("click", () => {
  autoRefresh = !autoRefresh;
  toggleAuto.textContent = `Auto: ${autoRefresh ? "On" : "Off"}`;
  schedule();
});

limitInput.addEventListener("change", refresh);

schedule();
refresh();
