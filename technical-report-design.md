# Technical Report View — Design

## Aesthetic Direction

**"Command Center"** — Dark cinematic UI, Bloomberg Terminal meets cybersecurity war room.

- **Fonts**: JetBrains Mono (headings, numbers, labels) + DM Sans (body text)
- **Palette**: Deep black (#060a13) base, emerald (#10b981) + cyan (#06b6d4) accents
- **Cards**: Dark slate (#0d1117) with subtle borders, no heavy shadows
- **Effects**: Subtle scanline overlay, gradient header rule, glow on trend line
- **Print**: Clean white background, no animations, page-break-aware

## Sections

```
01  Executive Summary     — Risk gauge (SVG arc), grade badge, 4 KPI cards
02  Severity Distribution — Horizontal bars + donut chart (all SVG, no lib)
03  Attack Surface        — 5 asset type cards with color-coded bottom bar
04  Scan Pipeline         — Meta grid + phase timeline (chips with status dots)
05  Risk Trend            — SVG area chart with gradient fill (30 days)
06  Top Open Findings     — Sortable table with severity pills, CVSS, CVE
07  Findings by Rule      — 2-col grid of detection template cards
08  Top Risk Issues       — Ranked list with severity dots + asset count
09  Recommendations       — Priority-tagged cards with severity border
```

## Data Sources

| Section                                                | API Endpoint                                            |
| ------------------------------------------------------ | ------------------------------------------------------- |
| KPIs, Severity, Assets, Trend, Issues, Recommendations | `GET /api/v1/tenants/{tid}/reports/executive`           |
| Findings table, Template grouping                      | `GET /api/v1/tenants/{tid}/reports/technical?limit=500` |
| Scan pipeline phases                                   | `GET /api/v1/tenants/{tid}/scans/{id}/progress`         |

## Route

```
/reports/technical-view → TechnicalReportView.vue
```

## Component Code

File: `frontend/src/views/reports/TechnicalReportView.vue`

```vue
<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from "vue";
import { useTenantStore } from "@/stores/tenant";
import apiClient from "@/api/client";
import { formatDate } from "@/utils/formatters";
import { SEVERITY_HEX, SEVERITY_ORDER, getRiskGrade } from "@/utils/severity";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

interface TopIssue {
  name: string;
  severity: SeverityLevel;
  affected_assets: number;
  template_id?: string;
}

interface Recommendation {
  priority: number;
  title: string;
  description: string;
  severity: SeverityLevel;
}

interface ScoreTrendPoint {
  date: string;
  score: number;
}

interface ExecutiveReport {
  risk_score: number;
  risk_grade: string;
  total_assets: number;
  total_findings: number;
  open_findings: number;
  asset_counts: Record<string, number>;
  finding_counts_by_severity: Record<SeverityLevel, number>;
  finding_counts_by_status: Record<string, number>;
  score_trend: ScoreTrendPoint[];
  top_issues: TopIssue[];
  recommendations: Recommendation[];
  generated_at: string;
}

interface TechnicalFinding {
  id: number;
  name: string;
  severity: SeverityLevel;
  cvss_score: number | null;
  cve_id: string | null;
  template_id: string | null;
  asset_identifier: string;
  asset_type: string;
  evidence: Record<string, unknown> | null;
  status: "open" | "suppressed" | "fixed";
  first_seen: string;
  last_seen: string;
  host: string | null;
  matched_at: string | null;
}

interface TechnicalReport {
  total_findings: number;
  findings: TechnicalFinding[];
  generated_at: string;
}

interface ScanPhase {
  phase: string;
  status: string;
  stats: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
}

interface ScanRun {
  id: number;
  status: string;
  triggered_by: string;
  started_at: string | null;
  completed_at: string | null;
  stats: Record<string, unknown> | null;
  created_at: string;
}

interface ScanProgress {
  scan_run: ScanRun;
  phases: ScanPhase[];
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const tenantStore = useTenantStore();
const currentTenantId = computed(() => tenantStore.currentTenantId);
const tenantName = computed(() => tenantStore.currentTenant?.name ?? "Unknown");

const loading = ref(true);
const error = ref("");
const executive = ref<ExecutiveReport | null>(null);
const technical = ref<TechnicalReport | null>(null);
const scanProgress = ref<ScanProgress | null>(null);
const isExporting = ref(false);

let controller: AbortController | null = null;

// ---------------------------------------------------------------------------
// Computed helpers
// ---------------------------------------------------------------------------

const riskGrade = computed(() => {
  if (!executive.value) return { letter: "—", color: "#6b7280" };
  return getRiskGrade(executive.value.risk_score);
});

const severityData = computed(() => {
  if (!executive.value) return [];
  const counts = executive.value.finding_counts_by_severity;
  const total = Object.values(counts).reduce((s, v) => s + v, 0) || 1;
  return SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: counts[sev] || 0,
    pct: Math.round(((counts[sev] || 0) / total) * 100),
    color: SEVERITY_HEX[sev],
  }));
});

const assetBreakdown = computed(() => {
  if (!executive.value) return [];
  const types = ["domain", "subdomain", "ip", "url", "service"] as const;
  const colors: Record<string, string> = {
    domain: "#3b82f6",
    subdomain: "#8b5cf6",
    ip: "#06b6d4",
    url: "#10b981",
    service: "#f59e0b",
  };
  const total =
    Object.values(executive.value.asset_counts).reduce((s, v) => s + v, 0) || 1;
  return types.map((t) => ({
    type: t,
    count: executive.value!.asset_counts[t] || 0,
    pct: Math.round(((executive.value!.asset_counts[t] || 0) / total) * 100),
    color: colors[t],
  }));
});

const phaseTimeline = computed(() => {
  if (!scanProgress.value) return [];
  return scanProgress.value.phases
    .filter((p) => p.status !== "pending")
    .map((p) => ({
      ...p,
      label: PHASE_NAMES[p.phase] || p.phase,
      duration:
        p.started_at && p.completed_at
          ? Math.round(
              (new Date(p.completed_at).getTime() -
                new Date(p.started_at).getTime()) /
                1000,
            )
          : null,
    }));
});

const scanDuration = computed(() => {
  const sr = scanProgress.value?.scan_run;
  if (!sr?.started_at || !sr?.completed_at) return "—";
  const secs = Math.round(
    (new Date(sr.completed_at).getTime() - new Date(sr.started_at).getTime()) /
      1000,
  );
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
});

const trendPath = computed(() => {
  if (!executive.value?.score_trend?.length) return "";
  const pts = executive.value.score_trend;
  const w = 600,
    h = 120;
  const xStep = w / Math.max(pts.length - 1, 1);
  return pts
    .map(
      (p, i) =>
        `${i === 0 ? "M" : "L"}${(i * xStep).toFixed(1)},${(h - (p.score / 100) * h).toFixed(1)}`,
    )
    .join(" ");
});

const trendAreaPath = computed(() => {
  if (!trendPath.value) return "";
  return `${trendPath.value} L600,120 L0,120 Z`;
});

const topFindings = computed(() => {
  if (!technical.value) return [];
  return technical.value.findings
    .filter((f) => f.status === "open")
    .slice(0, 15);
});

const findingsByTemplate = computed(() => {
  if (!technical.value) return [];
  const map = new Map<
    string,
    { name: string; severity: SeverityLevel; count: number; template: string }
  >();
  for (const f of technical.value.findings) {
    const key = f.template_id || f.name;
    const existing = map.get(key);
    if (existing) existing.count++;
    else
      map.set(key, {
        name: f.name,
        severity: f.severity,
        count: 1,
        template: f.template_id || "—",
      });
  }
  return [...map.values()]
    .sort((a, b) => {
      const so =
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      return so !== 0 ? so : b.count - a.count;
    })
    .slice(0, 20);
});

// ---------------------------------------------------------------------------
// Phase name map
// ---------------------------------------------------------------------------

const PHASE_NAMES: Record<string, string> = {
  "0": "Seed Ingestion",
  "1": "Passive Discovery",
  "1b": "GitHub Dorking",
  "1c": "WHOIS / RDAP",
  "1d": "Cloud Buckets",
  "1e": "Domain Permutation",
  "2": "DNS Bruteforce",
  "3": "DNS Resolution",
  "4": "HTTP Probing",
  "4b": "TLS Collection",
  "5": "Port Scanning",
  "5b": "CDN/WAF Detection",
  "5c": "Service Fingerprinting",
  "6": "Tech Fingerprinting",
  "6b": "Web Crawling",
  "6c": "Sensitive Paths",
  "7": "Visual Recon",
  "8": "Misconfig Detection",
  "9": "Vulnerability Scan",
  "10": "Correlation & Dedup",
  "11": "Risk Scoring",
  "12": "Diff & Alerting",
};

// ---------------------------------------------------------------------------
// Data fetching
// ---------------------------------------------------------------------------

async function loadReport() {
  if (!currentTenantId.value) return;
  loading.value = true;
  error.value = "";
  controller?.abort();
  controller = new AbortController();

  try {
    const tid = currentTenantId.value;
    const signal = controller.signal;

    const [execRes, techRes] = await Promise.all([
      apiClient.get<ExecutiveReport>(
        `/api/v1/tenants/${tid}/reports/executive`,
        { signal },
      ),
      apiClient.get<TechnicalReport>(
        `/api/v1/tenants/${tid}/reports/technical?limit=500`,
        { signal },
      ),
    ]);

    executive.value = execRes.data;
    technical.value = techRes.data;

    // Try to load latest scan progress (optional — don't fail report)
    try {
      const scansRes = await apiClient.get<{ data: ScanRun[] }>(
        `/api/v1/tenants/${tid}/scans?page=1&page_size=1`,
        { signal },
      );
      const runs = scansRes.data?.data || scansRes.data;
      if (Array.isArray(runs) && runs.length > 0) {
        const progressRes = await apiClient.get<ScanProgress>(
          `/api/v1/tenants/${tid}/scans/${runs[0].id}/progress`,
          { signal },
        );
        scanProgress.value = progressRes.data;
      }
    } catch {
      /* scan progress is optional */
    }
  } catch (e: unknown) {
    if (e instanceof Error && e.name === "CanceledError") return;
    error.value = e instanceof Error ? e.message : "Failed to load report data";
  } finally {
    loading.value = false;
  }
}

async function exportPdf() {
  if (!currentTenantId.value) return;
  isExporting.value = true;
  try {
    const res = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/reports/export/pdf?report_type=technical`,
      { responseType: "blob", timeout: 120000 },
    );
    const url = URL.createObjectURL(res.data as Blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `technical-report-${new Date().toISOString().slice(0, 10)}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    error.value = "PDF export failed";
  } finally {
    isExporting.value = false;
  }
}

function printReport() {
  window.print();
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

onMounted(loadReport);
onUnmounted(() => controller?.abort());
watch(currentTenantId, loadReport);
</script>

<template>
  <div class="report-root">
    <!-- Scanline texture overlay (screen only) -->
    <div class="scanline-overlay print:hidden" aria-hidden="true" />

    <!-- ================================================================= -->
    <!-- HEADER                                                            -->
    <!-- ================================================================= -->
    <header class="report-header">
      <div class="header-grid">
        <div class="brand-block">
          <div class="brand-logo">
            <svg viewBox="0 0 40 40" class="w-10 h-10">
              <circle
                cx="20"
                cy="20"
                r="18"
                fill="none"
                stroke="url(#hg)"
                stroke-width="2"
              />
              <path
                d="M12 20 L20 12 L28 20 L20 28Z"
                fill="url(#hg)"
                opacity="0.7"
              />
              <circle cx="20" cy="20" r="4" fill="#10b981" />
              <defs>
                <linearGradient id="hg" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stop-color="#10b981" />
                  <stop offset="100%" stop-color="#06b6d4" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          <div>
            <h1 class="brand-title">PushingTorPod</h1>
            <p class="brand-sub">External Attack Surface Management</p>
          </div>
        </div>

        <div class="header-meta">
          <div class="meta-item">
            <span class="meta-label">Organization</span>
            <span class="meta-value">{{ tenantName }}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Report Type</span>
            <span class="meta-value accent">Technical Assessment</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Generated</span>
            <span class="meta-value">{{
              executive ? formatDate(executive.generated_at, "datetime") : "—"
            }}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Classification</span>
            <span
              class="meta-value text-red-400 font-bold tracking-widest text-xs"
              >CONFIDENTIAL</span
            >
          </div>
        </div>

        <div class="header-actions print:hidden">
          <button @click="printReport" class="action-btn">
            <svg
              class="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"
              />
            </svg>
            Print
          </button>
          <button
            @click="exportPdf"
            :disabled="isExporting"
            class="action-btn action-btn-primary"
          >
            <svg
              class="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
            {{ isExporting ? "Exporting…" : "Export PDF" }}
          </button>
        </div>
      </div>
      <div class="header-rule" />
    </header>

    <!-- Loading -->
    <div v-if="loading" class="loading-state">
      <div class="pulse-ring" />
      <p class="loading-text">Compiling threat intelligence data…</p>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="error-state" role="alert">
      <p>{{ error }}</p>
      <button @click="loadReport" class="action-btn mt-4">Retry</button>
    </div>

    <!-- Report body -->
    <main v-else-if="executive" class="report-body">
      <!-- 01 EXECUTIVE SUMMARY -->
      <section class="report-section">
        <h2 class="section-title">
          <span class="section-num">01</span> Executive Summary
        </h2>
        <div class="kpi-grid">
          <!-- Risk Gauge -->
          <div class="kpi-card kpi-card-xl">
            <div class="gauge-container">
              <svg viewBox="0 0 200 120" class="gauge-svg">
                <defs>
                  <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stop-color="#10b981" />
                    <stop offset="50%" stop-color="#eab308" />
                    <stop offset="100%" stop-color="#dc2626" />
                  </linearGradient>
                </defs>
                <path
                  d="M20 100 A80 80 0 0 1 180 100"
                  fill="none"
                  stroke="#1e293b"
                  stroke-width="12"
                  stroke-linecap="round"
                />
                <path
                  d="M20 100 A80 80 0 0 1 180 100"
                  fill="none"
                  stroke="url(#gaugeGrad)"
                  stroke-width="12"
                  stroke-linecap="round"
                  :stroke-dasharray="`${(executive.risk_score / 100) * 251.2} 251.2`"
                  class="gauge-fill"
                />
                <text
                  x="100"
                  y="85"
                  text-anchor="middle"
                  class="gauge-score"
                  :fill="riskGrade.color"
                >
                  {{ Math.round(executive.risk_score) }}
                </text>
                <text
                  x="100"
                  y="105"
                  text-anchor="middle"
                  class="gauge-label"
                  fill="#94a3b8"
                >
                  Risk Score
                </text>
              </svg>
              <div
                class="grade-badge"
                :style="{
                  borderColor: riskGrade.color,
                  color: riskGrade.color,
                }"
              >
                {{ executive.risk_grade }}
              </div>
            </div>
          </div>
          <!-- KPIs -->
          <div class="kpi-card">
            <div class="kpi-icon kpi-icon-blue">
              <svg
                class="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"
                />
              </svg>
            </div>
            <div class="kpi-value">
              {{ executive.total_assets.toLocaleString() }}
            </div>
            <div class="kpi-label">Total Assets</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-icon kpi-icon-red">
              <svg
                class="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
            </div>
            <div class="kpi-value">
              {{ executive.total_findings.toLocaleString() }}
            </div>
            <div class="kpi-label">Total Findings</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-icon kpi-icon-amber">
              <svg
                class="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M13 10V3L4 14h7v7l9-11h-7z"
                />
              </svg>
            </div>
            <div class="kpi-value">
              {{ executive.open_findings.toLocaleString() }}
            </div>
            <div class="kpi-label">Open Findings</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-icon kpi-icon-emerald">
              <svg
                class="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <div class="kpi-value">
              {{
                (
                  executive.finding_counts_by_status["fixed"] || 0
                ).toLocaleString()
              }}
            </div>
            <div class="kpi-label">Fixed</div>
          </div>
        </div>
      </section>

      <!-- 02 SEVERITY DISTRIBUTION -->
      <section class="report-section">
        <h2 class="section-title">
          <span class="section-num">02</span> Severity Distribution
        </h2>
        <div class="severity-grid">
          <div class="severity-bars">
            <div
              v-for="item in severityData"
              :key="item.severity"
              class="sev-row"
            >
              <div class="sev-label">
                <span class="sev-dot" :style="{ background: item.color }" />
                <span class="sev-name">{{ item.severity }}</span>
                <span class="sev-count">{{ item.count }}</span>
              </div>
              <div class="sev-track">
                <div
                  class="sev-fill"
                  :style="{ width: `${item.pct}%`, background: item.color }"
                />
              </div>
              <span class="sev-pct">{{ item.pct }}%</span>
            </div>
          </div>
          <div class="donut-container">
            <svg viewBox="0 0 200 200" class="donut-svg">
              <circle
                cx="100"
                cy="100"
                r="70"
                fill="none"
                stroke="#1e293b"
                stroke-width="24"
              />
              <template v-for="(item, i) in severityData" :key="item.severity">
                <circle
                  cx="100"
                  cy="100"
                  r="70"
                  fill="none"
                  :stroke="item.color"
                  stroke-width="24"
                  :stroke-dasharray="`${(item.pct / 100) * 439.8} 439.8`"
                  :stroke-dashoffset="`${-severityData.slice(0, i).reduce((s, d) => s + (d.pct / 100) * 439.8, 0)}`"
                  stroke-linecap="round"
                  class="donut-segment"
                />
              </template>
              <text
                x="100"
                y="95"
                text-anchor="middle"
                class="donut-center-num"
                fill="#f1f5f9"
              >
                {{ executive.total_findings }}
              </text>
              <text
                x="100"
                y="115"
                text-anchor="middle"
                class="donut-center-label"
                fill="#64748b"
              >
                findings
              </text>
            </svg>
          </div>
        </div>
      </section>

      <!-- 03 ASSET INVENTORY -->
      <section class="report-section">
        <h2 class="section-title">
          <span class="section-num">03</span> Attack Surface Inventory
        </h2>
        <div class="asset-grid">
          <div
            v-for="item in assetBreakdown"
            :key="item.type"
            class="asset-card"
          >
            <div
              class="asset-bar"
              :style="{
                background: item.color,
                width: `${Math.max(item.pct, 4)}%`,
              }"
            />
            <div class="asset-info">
              <span class="asset-type">{{ item.type }}</span>
              <span class="asset-count" :style="{ color: item.color }">{{
                item.count.toLocaleString()
              }}</span>
            </div>
          </div>
        </div>
      </section>

      <!-- 04 SCAN PIPELINE -->
      <section v-if="scanProgress" class="report-section">
        <h2 class="section-title">
          <span class="section-num">04</span> Scan Pipeline Overview
        </h2>
        <div class="scan-meta-grid">
          <div class="scan-meta-item">
            <span class="meta-label">Scan ID</span>
            <span class="meta-value font-mono"
              >#{{ scanProgress.scan_run.id }}</span
            >
          </div>
          <div class="scan-meta-item">
            <span class="meta-label">Status</span>
            <span
              class="meta-value"
              :class="
                scanProgress.scan_run.status === 'completed'
                  ? 'text-emerald-400'
                  : 'text-amber-400'
              "
            >
              {{ scanProgress.scan_run.status.toUpperCase() }}
            </span>
          </div>
          <div class="scan-meta-item">
            <span class="meta-label">Duration</span>
            <span class="meta-value font-mono">{{ scanDuration }}</span>
          </div>
          <div class="scan-meta-item">
            <span class="meta-label">Triggered</span>
            <span class="meta-value">{{
              scanProgress.scan_run.triggered_by || "manual"
            }}</span>
          </div>
        </div>
        <div class="phase-timeline">
          <div
            v-for="phase in phaseTimeline"
            :key="phase.phase"
            class="phase-node"
            :class="{
              'phase-completed': phase.status === 'completed',
              'phase-failed': phase.status === 'failed',
              'phase-skipped': phase.status === 'skipped',
              'phase-running': phase.status === 'running',
            }"
          >
            <div class="phase-dot">
              <svg
                v-if="phase.status === 'completed'"
                class="w-3 h-3"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fill-rule="evenodd"
                  d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                  clip-rule="evenodd"
                />
              </svg>
              <svg
                v-else-if="phase.status === 'failed'"
                class="w-3 h-3"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fill-rule="evenodd"
                  d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                  clip-rule="evenodd"
                />
              </svg>
              <span v-else-if="phase.status === 'skipped'" class="text-[10px]"
                >—</span
              >
              <div v-else class="phase-pulse" />
            </div>
            <div class="phase-info">
              <span class="phase-name">{{ phase.label }}</span>
              <span v-if="phase.duration !== null" class="phase-dur"
                >{{ phase.duration }}s</span
              >
            </div>
          </div>
        </div>
      </section>

      <!-- 05 RISK TREND -->
      <section v-if="executive.score_trend?.length > 1" class="report-section">
        <h2 class="section-title">
          <span class="section-num">05</span> Risk Score Trend (30 days)
        </h2>
        <div class="trend-chart-container">
          <svg
            viewBox="0 0 600 120"
            class="trend-svg"
            preserveAspectRatio="none"
          >
            <defs>
              <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#10b981" stop-opacity="0.3" />
                <stop offset="100%" stop-color="#10b981" stop-opacity="0" />
              </linearGradient>
            </defs>
            <path :d="trendAreaPath" fill="url(#trendFill)" />
            <path
              :d="trendPath"
              fill="none"
              stroke="#10b981"
              stroke-width="2"
              class="trend-line"
            />
          </svg>
          <div class="trend-labels">
            <span>{{
              formatDate(executive.score_trend[0]?.date, "date")
            }}</span>
            <span>{{
              formatDate(
                executive.score_trend[executive.score_trend.length - 1]?.date,
                "date",
              )
            }}</span>
          </div>
        </div>
      </section>

      <!-- 06 TOP FINDINGS -->
      <section class="report-section">
        <h2 class="section-title">
          <span class="section-num">06</span> Top Open Findings
        </h2>
        <div class="findings-table-wrap">
          <table class="findings-table">
            <thead>
              <tr>
                <th class="w-24">Severity</th>
                <th>Finding</th>
                <th class="w-48">Asset</th>
                <th class="w-20 text-center">CVSS</th>
                <th class="w-28">CVE</th>
                <th class="w-28">First Seen</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="f in topFindings" :key="f.id">
                <td>
                  <span
                    class="sev-pill"
                    :style="{
                      background: SEVERITY_HEX[f.severity] + '22',
                      color: SEVERITY_HEX[f.severity],
                      borderColor: SEVERITY_HEX[f.severity] + '44',
                    }"
                  >
                    {{ f.severity }}
                  </span>
                </td>
                <td class="finding-name">{{ f.name }}</td>
                <td
                  class="font-mono text-xs text-slate-400 truncate max-w-[12rem]"
                >
                  {{ f.asset_identifier }}
                </td>
                <td class="text-center font-mono">
                  <span
                    v-if="f.cvss_score !== null"
                    :class="
                      f.cvss_score >= 9
                        ? 'text-red-400'
                        : f.cvss_score >= 7
                          ? 'text-orange-400'
                          : 'text-slate-400'
                    "
                  >
                    {{ f.cvss_score.toFixed(1) }}
                  </span>
                  <span v-else class="text-slate-600">—</span>
                </td>
                <td class="font-mono text-xs">{{ f.cve_id || "—" }}</td>
                <td class="text-xs text-slate-500">
                  {{ formatDate(f.first_seen, "date") }}
                </td>
              </tr>
              <tr v-if="topFindings.length === 0">
                <td colspan="6" class="text-center text-slate-500 py-8">
                  No open findings
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- 07 FINDINGS BY TEMPLATE -->
      <section v-if="findingsByTemplate.length" class="report-section">
        <h2 class="section-title">
          <span class="section-num">07</span> Findings by Detection Rule
        </h2>
        <div class="template-grid">
          <div
            v-for="item in findingsByTemplate"
            :key="item.template"
            class="template-card"
          >
            <div class="template-header">
              <span
                class="sev-dot"
                :style="{ background: SEVERITY_HEX[item.severity] }"
              />
              <span class="template-name">{{ item.name }}</span>
              <span
                class="template-count"
                :style="{ color: SEVERITY_HEX[item.severity] }"
                >{{ item.count }}</span
              >
            </div>
            <div class="template-id">{{ item.template }}</div>
          </div>
        </div>
      </section>

      <!-- 08 TOP ISSUES -->
      <section v-if="executive.top_issues?.length" class="report-section">
        <h2 class="section-title">
          <span class="section-num">08</span> Top Risk Issues
        </h2>
        <div class="issues-list">
          <div
            v-for="(issue, idx) in executive.top_issues"
            :key="idx"
            class="issue-row"
          >
            <div class="issue-rank">{{ idx + 1 }}</div>
            <span
              class="sev-dot"
              :style="{ background: SEVERITY_HEX[issue.severity] }"
            />
            <div class="issue-info">
              <span class="issue-name">{{ issue.name }}</span>
              <span class="issue-assets"
                >{{ issue.affected_assets }} asset{{
                  issue.affected_assets !== 1 ? "s" : ""
                }}</span
              >
            </div>
          </div>
        </div>
      </section>

      <!-- 09 RECOMMENDATIONS -->
      <section
        v-if="executive.recommendations?.length"
        class="report-section page-break-before"
      >
        <h2 class="section-title">
          <span class="section-num">09</span> Recommendations
        </h2>
        <div class="rec-list">
          <div
            v-for="rec in executive.recommendations"
            :key="rec.priority"
            class="rec-card"
          >
            <div
              class="rec-priority"
              :style="{ borderColor: SEVERITY_HEX[rec.severity] }"
            >
              P{{ rec.priority }}
            </div>
            <div class="rec-body">
              <h4 class="rec-title">{{ rec.title }}</h4>
              <p class="rec-desc">{{ rec.description }}</p>
            </div>
          </div>
        </div>
      </section>

      <!-- FOOTER -->
      <footer class="report-footer">
        <div class="footer-rule" />
        <div class="footer-content">
          <span>PushingTorPod EASM — Technical Assessment Report</span>
          <span
            >{{ tenantName }} —
            {{ new Date().toISOString().slice(0, 10) }}</span
          >
          <span class="text-red-400/60">CONFIDENTIAL</span>
        </div>
      </footer>
    </main>
  </div>
</template>

<style scoped>
/* ====================================================================== */
/* FONTS                                                                  */
/* ====================================================================== */
@import url("https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,500;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;600&display=swap");

/* ====================================================================== */
/* ROOT                                                                   */
/* ====================================================================== */
.report-root {
  --bg-deep: #060a13;
  --bg-card: #0d1117;
  --bg-card-hover: #111827;
  --border: #1e293b;
  --border-subtle: #151d2b;
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-dim: #475569;
  --accent: #10b981;
  --accent-cyan: #06b6d4;
  font-family: "DM Sans", system-ui, sans-serif;
  background: var(--bg-deep);
  color: var(--text-primary);
  min-height: 100vh;
  position: relative;
  padding: 0 2rem 4rem;
}

.scanline-overlay {
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 50;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(16, 185, 129, 0.015) 2px,
    rgba(16, 185, 129, 0.015) 4px
  );
}

/* HEADER */
.report-header {
  padding: 2.5rem 0 0;
  max-width: 1200px;
  margin: 0 auto;
}
.header-grid {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 2rem;
  flex-wrap: wrap;
}
.brand-block {
  display: flex;
  align-items: center;
  gap: 1rem;
}
.brand-title {
  font-family: "JetBrains Mono", monospace;
  font-size: 1.5rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  background: linear-gradient(135deg, #10b981, #06b6d4);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.brand-sub {
  font-size: 0.75rem;
  color: var(--text-dim);
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.header-meta {
  display: flex;
  gap: 2rem;
  flex-wrap: wrap;
}
.meta-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.meta-label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-dim);
  font-family: "JetBrains Mono", monospace;
}
.meta-value {
  font-size: 0.85rem;
  color: var(--text-secondary);
}
.meta-value.accent {
  color: var(--accent);
}
.header-actions {
  display: flex;
  gap: 0.75rem;
}

.action-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  font-size: 0.8rem;
  font-family: "JetBrains Mono", monospace;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-card);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.2s;
}
.action-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}
.action-btn-primary {
  background: linear-gradient(135deg, #10b981, #059669);
  border-color: transparent;
  color: #fff;
}
.action-btn-primary:hover {
  filter: brightness(1.15);
  color: #fff;
}
.action-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.header-rule {
  height: 1px;
  margin-top: 1.5rem;
  background: linear-gradient(90deg, var(--accent), transparent 60%);
}

/* LOADING/ERROR */
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 60vh;
  gap: 1.5rem;
}
.pulse-ring {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  border: 2px solid var(--accent);
  animation: pulse-ring 1.5s ease-out infinite;
}
@keyframes pulse-ring {
  0% {
    transform: scale(0.8);
    opacity: 1;
  }
  100% {
    transform: scale(1.8);
    opacity: 0;
  }
}
.loading-text {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.8rem;
  color: var(--text-dim);
  letter-spacing: 0.05em;
}
.error-state {
  max-width: 1200px;
  margin: 4rem auto;
  padding: 2rem;
  background: rgba(220, 38, 38, 0.08);
  border: 1px solid rgba(220, 38, 38, 0.2);
  border-radius: 8px;
  text-align: center;
  color: #fca5a5;
}

/* BODY */
.report-body {
  max-width: 1200px;
  margin: 0 auto;
}
.report-section {
  margin-top: 3rem;
}
.section-title {
  font-family: "JetBrains Mono", monospace;
  font-size: 1.1rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
}
.section-num {
  font-size: 0.7rem;
  color: var(--accent);
  border: 1px solid var(--accent);
  border-radius: 4px;
  padding: 0.15rem 0.4rem;
  letter-spacing: 0.05em;
}

/* KPI */
.kpi-grid {
  display: grid;
  grid-template-columns: 1.6fr repeat(4, 1fr);
  gap: 1rem;
}
.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.75rem;
  transition: border-color 0.2s;
}
.kpi-card:hover {
  border-color: var(--border);
}
.kpi-card-xl {
  align-items: center;
  justify-content: center;
  padding: 1rem;
}
.kpi-icon {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.kpi-icon-blue {
  background: rgba(59, 130, 246, 0.15);
  color: #60a5fa;
}
.kpi-icon-red {
  background: rgba(220, 38, 38, 0.15);
  color: #f87171;
}
.kpi-icon-amber {
  background: rgba(234, 179, 8, 0.15);
  color: #fbbf24;
}
.kpi-icon-emerald {
  background: rgba(16, 185, 129, 0.15);
  color: #34d399;
}
.kpi-value {
  font-family: "JetBrains Mono", monospace;
  font-size: 1.75rem;
  font-weight: 600;
  line-height: 1;
}
.kpi-label {
  font-size: 0.75rem;
  color: var(--text-dim);
  letter-spacing: 0.05em;
}

/* GAUGE */
.gauge-container {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
}
.gauge-svg {
  width: 180px;
}
.gauge-score {
  font-family: "JetBrains Mono", monospace;
  font-size: 2rem;
  font-weight: 700;
}
.gauge-label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}
.gauge-fill {
  transition: stroke-dasharray 1.5s ease-out;
}
.grade-badge {
  position: absolute;
  top: 4px;
  right: 4px;
  font-family: "JetBrains Mono", monospace;
  font-size: 0.9rem;
  font-weight: 700;
  border: 2px solid;
  border-radius: 6px;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
}

/* SEVERITY */
.severity-grid {
  display: grid;
  grid-template-columns: 1fr 240px;
  gap: 2rem;
  align-items: center;
}
.severity-bars {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.sev-row {
  display: grid;
  grid-template-columns: 140px 1fr 40px;
  align-items: center;
  gap: 0.75rem;
}
.sev-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.sev-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.sev-name {
  font-size: 0.8rem;
  text-transform: capitalize;
  color: var(--text-secondary);
}
.sev-count {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.75rem;
  color: var(--text-dim);
}
.sev-track {
  height: 6px;
  background: var(--border-subtle);
  border-radius: 3px;
  overflow: hidden;
}
.sev-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 1s ease-out;
}
.sev-pct {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.7rem;
  color: var(--text-dim);
  text-align: right;
}
.donut-container {
  display: flex;
  align-items: center;
  justify-content: center;
}
.donut-svg {
  width: 200px;
  height: 200px;
}
.donut-segment {
  transition: stroke-dasharray 1s ease-out;
}
.donut-center-num {
  font-family: "JetBrains Mono", monospace;
  font-size: 1.8rem;
  font-weight: 700;
}
.donut-center-label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

/* ASSETS */
.asset-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 0.75rem;
}
.asset-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 1rem;
  position: relative;
  overflow: hidden;
}
.asset-bar {
  position: absolute;
  bottom: 0;
  left: 0;
  height: 3px;
  border-radius: 0 3px 0 0;
  transition: width 1s ease-out;
}
.asset-info {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}
.asset-type {
  font-size: 0.75rem;
  color: var(--text-dim);
  text-transform: capitalize;
}
.asset-count {
  font-family: "JetBrains Mono", monospace;
  font-size: 1.3rem;
  font-weight: 600;
}

/* SCAN PIPELINE */
.scan-meta-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.scan-meta-item {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.phase-timeline {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.phase-node {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 0.75rem;
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  font-size: 0.75rem;
}
.phase-dot {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.phase-completed .phase-dot {
  background: rgba(16, 185, 129, 0.2);
  color: #10b981;
}
.phase-failed .phase-dot {
  background: rgba(220, 38, 38, 0.2);
  color: #dc2626;
}
.phase-skipped .phase-dot {
  background: rgba(100, 116, 139, 0.2);
  color: #64748b;
}
.phase-running .phase-dot {
  background: rgba(6, 182, 212, 0.2);
}
.phase-pulse {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #06b6d4;
  animation: pulse-ring 1.2s ease-out infinite;
}
.phase-info {
  display: flex;
  flex-direction: column;
}
.phase-name {
  color: var(--text-secondary);
  font-size: 0.72rem;
}
.phase-dur {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.65rem;
  color: var(--text-dim);
}

/* TREND */
.trend-chart-container {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 1.5rem;
}
.trend-svg {
  width: 100%;
  height: 120px;
}
.trend-line {
  filter: drop-shadow(0 0 6px rgba(16, 185, 129, 0.4));
}
.trend-labels {
  display: flex;
  justify-content: space-between;
  margin-top: 0.5rem;
  font-size: 0.65rem;
  color: var(--text-dim);
  font-family: "JetBrains Mono", monospace;
}

/* FINDINGS TABLE */
.findings-table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
}
.findings-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8rem;
}
.findings-table thead {
  background: #0a0f18;
}
.findings-table th {
  padding: 0.75rem 1rem;
  text-align: left;
  font-family: "JetBrains Mono", monospace;
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
}
.findings-table td {
  padding: 0.6rem 1rem;
  border-bottom: 1px solid var(--border-subtle);
  color: var(--text-secondary);
}
.findings-table tr:hover td {
  background: rgba(16, 185, 129, 0.03);
}
.findings-table tr:last-child td {
  border-bottom: none;
}
.sev-pill {
  display: inline-block;
  font-family: "JetBrains Mono", monospace;
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  border: 1px solid;
  letter-spacing: 0.05em;
}
.finding-name {
  color: var(--text-primary);
  font-weight: 500;
  max-width: 24rem;
}

/* TEMPLATES */
.template-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.5rem;
}
.template-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 0.75rem 1rem;
}
.template-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.template-name {
  flex: 1;
  font-size: 0.8rem;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.template-count {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.85rem;
  font-weight: 600;
}
.template-id {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.65rem;
  color: var(--text-dim);
  margin-top: 0.2rem;
}

/* ISSUES */
.issues-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.issue-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
}
.issue-rank {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.7rem;
  color: var(--text-dim);
  width: 20px;
  text-align: center;
}
.issue-info {
  flex: 1;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.issue-name {
  font-size: 0.85rem;
  color: var(--text-primary);
}
.issue-assets {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.7rem;
  color: var(--text-dim);
}

/* RECOMMENDATIONS */
.rec-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.rec-card {
  display: flex;
  gap: 1rem;
  padding: 1rem 1.25rem;
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
}
.rec-priority {
  font-family: "JetBrains Mono", monospace;
  font-size: 0.7rem;
  font-weight: 600;
  color: var(--text-dim);
  border-left: 3px solid;
  padding-left: 0.5rem;
  flex-shrink: 0;
}
.rec-title {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 0.25rem;
}
.rec-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
  line-height: 1.5;
}

/* FOOTER */
.report-footer {
  margin-top: 4rem;
  max-width: 1200px;
  margin-left: auto;
  margin-right: auto;
}
.footer-rule {
  height: 1px;
  background: var(--border);
}
.footer-content {
  display: flex;
  justify-content: space-between;
  padding: 1rem 0;
  font-size: 0.7rem;
  color: var(--text-dim);
  font-family: "JetBrains Mono", monospace;
}

/* PRINT */
@media print {
  .report-root {
    background: #fff !important;
    color: #1e293b !important;
    padding: 0 !important;
    --bg-card: #f8fafc;
    --border-subtle: #e2e8f0;
    --border: #cbd5e1;
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --text-dim: #94a3b8;
  }
  .scanline-overlay {
    display: none !important;
  }
  .brand-title {
    background: none !important;
    -webkit-text-fill-color: #0f172a !important;
  }
  .header-rule,
  .footer-rule {
    background: #e2e8f0 !important;
  }
  .gauge-score {
    fill: #0f172a !important;
  }
  .kpi-value {
    color: #0f172a !important;
  }
  .report-section {
    break-inside: avoid;
  }
  .page-break-before {
    break-before: page;
  }
  .findings-table thead {
    background: #f1f5f9 !important;
  }
  .trend-line {
    filter: none !important;
  }
}

/* RESPONSIVE */
@media (max-width: 1024px) {
  .kpi-grid {
    grid-template-columns: repeat(3, 1fr);
  }
  .kpi-card-xl {
    grid-column: span 3;
  }
  .severity-grid {
    grid-template-columns: 1fr;
  }
  .asset-grid {
    grid-template-columns: repeat(3, 1fr);
  }
  .template-grid {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 768px) {
  .report-root {
    padding: 0 1rem 2rem;
  }
  .kpi-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .kpi-card-xl {
    grid-column: span 2;
  }
  .asset-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .scan-meta-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .header-grid {
    flex-direction: column;
  }
}
</style>
```

## Router Addition

Add to `frontend/src/router/index.ts` inside the DashboardLayout children:

```typescript
{
  path: '/reports/technical-view',
  name: 'TechnicalReportView',
  component: () => import('@/views/reports/TechnicalReportView.vue'),
  meta: { requiresAuth: true, title: 'Technical Report' },
},
```
