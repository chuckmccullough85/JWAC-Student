"use strict";

const loginView = document.querySelector("#login-view");
const workspaceView = document.querySelector("#workspace-view");
const loginForm = document.querySelector("#login-form");
const logoutButton = document.querySelector("#logout-button");
const searchForm = document.querySelector("#search-form");
const reportList = document.querySelector("#report-list");
const reportDetail = document.querySelector("#report-detail");
const reportEmpty = document.querySelector("#report-empty");
const analyticsButton = document.querySelector("#analytics-button");
const uploadForm = document.querySelector("#upload-form");

let selectedReportId = null;
let serviceState = "vulnerable";

function setMessage(selector, text, type = "") {
  const element = document.querySelector(selector);
  element.textContent = text;
  element.className = `message ${type}`.trim();
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({ error: "The service returned an unreadable response." }));
  if (!response.ok) {
    const error = new Error(body.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}

function showWorkspace(user) {
  document.querySelector("#session-user").textContent = `${user.username} · ${user.role}`;
  loginView.hidden = true;
  workspaceView.hidden = false;
  logoutButton.hidden = false;
}

function showLogin() {
  document.querySelector("#session-user").textContent = "Not signed in";
  loginView.hidden = false;
  workspaceView.hidden = true;
  logoutButton.hidden = true;
  selectedReportId = null;
}

function renderReports(reports) {
  reportList.replaceChildren();
  document.querySelector("#result-count").textContent = `${reports.length} ${reports.length === 1 ? "report" : "reports"}`;
  if (!reports.length) {
    const empty = document.createElement("p");
    empty.className = "message";
    empty.textContent = "No reports matched this search.";
    reportList.append(empty);
    return;
  }
  for (const report of reports) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "report-item";
    button.dataset.reportId = report.id;
    const title = document.createElement("strong");
    title.textContent = report.title;
    const id = document.createElement("span");
    id.textContent = `Report ${report.id}`;
    const summary = document.createElement("span");
    summary.textContent = report.summary;
    const owner = document.createElement("span");
    owner.textContent = `Owner ID ${report.owner_id}`;
    button.append(title, id, summary, owner);
    button.addEventListener("click", () => loadReport(report.id, button));
    reportList.append(button);
  }
}

async function loadReports(query = "") {
  try {
    const body = await api(`/search?q=${encodeURIComponent(query)}`);
    renderReports(body.reports || []);
  } catch (error) {
    if (error.status === 401) showLogin();
    setMessage("#report-message", error.message, "error");
  }
}

async function loadReport(reportId, selectedButton) {
  setMessage("#report-message", "");
  try {
    const body = await api(`/reports/${reportId}`);
    const report = body.report;
    selectedReportId = report.id;
    document.querySelectorAll(".report-item").forEach(item => item.classList.remove("selected"));
    selectedButton?.classList.add("selected");
    document.querySelector("#report-id").textContent = `Report ${report.id}`;
    document.querySelector("#report-classification").textContent = report.classification.replaceAll("-", " ");
    document.querySelector("#report-title").textContent = report.title;
    document.querySelector("#report-owner").textContent = `Partner account ${report.owner_id}`;
    document.querySelector("#report-analyst").textContent = report.assigned_analyst_id ? `Analyst account ${report.assigned_analyst_id}` : "Not assigned";
    document.querySelector("#report-summary").textContent = report.summary;
    document.querySelector("#analytics-result").textContent = "No score requested";
    reportEmpty.hidden = true;
    reportDetail.hidden = false;
  } catch (error) {
    setMessage("#report-message", error.message, "error");
  }
}

loginForm.addEventListener("submit", async event => {
  event.preventDefault();
  setMessage("#login-message", "Signing in…");
  try {
    const body = await api("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#username").value,
        password: document.querySelector("#password").value,
      }),
    });
    loginForm.reset();
    setMessage("#login-message", "");
    showWorkspace(body.user);
    await loadReports();
  } catch (error) {
    setMessage("#login-message", error.message, "error");
  }
});

logoutButton.addEventListener("click", async () => {
  try { await api("/logout", { method: "POST" }); } catch (_) { /* Session still clears in the client. */ }
  showLogin();
});

searchForm.addEventListener("submit", event => {
  event.preventDefault();
  loadReports(document.querySelector("#search-input").value);
});

analyticsButton.addEventListener("click", async () => {
  if (!selectedReportId) return;
  document.querySelector("#analytics-result").textContent = "Requesting score…";
  const query = serviceState === "remediated"
    ? `report_id=${selectedReportId}`
    : `url=${encodeURIComponent(`http://127.0.0.1:5101/metrics/${selectedReportId}`)}`;
  try {
    const body = await api(`/analytics/fetch?${query}`);
    const score = body.score ?? body.metric ?? "Available";
    document.querySelector("#analytics-result").textContent = `Score: ${score}`;
  } catch (error) {
    document.querySelector("#analytics-result").textContent = error.message;
  }
});

uploadForm.addEventListener("submit", async event => {
  event.preventDefault();
  setMessage("#upload-message", "Submitting…");
  const data = new FormData(uploadForm);
  try {
    const body = await api("/documents", { method: "POST", body: data });
    setMessage("#upload-message", `Stored as ${body.stored_as}`, "success");
    uploadForm.reset();
  } catch (error) {
    setMessage("#upload-message", error.message, "error");
  }
});

api("/health")
  .then(body => {
    serviceState = body.state;
    document.querySelector("#service-status").textContent = "Service available";
  })
  .catch(() => { document.querySelector("#service-status").textContent = "Service unavailable"; });
