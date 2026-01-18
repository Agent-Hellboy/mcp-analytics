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
      eventsBody.innerHTML = '<tr><td colspan="4" class="empty">No data yet.</td></tr>';
      return;
    }

    eventsBody.innerHTML = events
      .map((event) => {
        return `
          <tr>
            <td>${new Date(event.timestamp).toLocaleString()}</td>
            <td>${event.source || "-"}</td>
            <td>${event.event_type || "-"}</td>
            <td><pre>${formatPayload(event.payload)}</pre></td>
          </tr>`;
      })
      .join("");
  } catch (err) {
    eventsBody.innerHTML = '<tr><td colspan="4" class="empty">Unable to load events.</td></tr>';
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
