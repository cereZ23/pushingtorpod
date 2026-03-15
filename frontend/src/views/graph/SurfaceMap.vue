<script setup lang="ts">
import {
  ref,
  computed,
  onMounted,
  onBeforeUnmount,
  watch,
  nextTick,
} from "vue";
import { select } from "d3-selection";
import type { Selection } from "d3-selection";
import { zoom, zoomIdentity } from "d3-zoom";
import type { ZoomBehavior, D3ZoomEvent } from "d3-zoom";
import { drag } from "d3-drag";
import type { D3DragEvent } from "d3-drag";
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
} from "d3-force";
import type { Simulation } from "d3-force";
import { useGraphStore } from "@/stores/graph";
import type { GraphNode, SimulationEdge, AssetNodeType } from "@/stores/graph";

// ------------------------------------------------------------------ constants
const NODE_COLORS: Record<AssetNodeType, string> = {
  domain: "#3b82f6", // blue-500
  subdomain: "#06b6d4", // cyan-500
  ip: "#22c55e", // green-500
  service: "#f97316", // orange-500
  url: "#a855f7", // purple-500
};

const NODE_COLORS_DARK: Record<AssetNodeType, string> = {
  domain: "#60a5fa", // blue-400
  subdomain: "#22d3ee", // cyan-400
  ip: "#4ade80", // green-400
  service: "#fb923c", // orange-400
  url: "#c084fc", // purple-400
};

const LEGEND_ITEMS: { type: AssetNodeType; label: string }[] = [
  { type: "domain", label: "Domain" },
  { type: "subdomain", label: "Subdomain" },
  { type: "ip", label: "IP Address" },
  { type: "service", label: "Service" },
  { type: "url", label: "URL" },
];

const REL_TYPE_LABELS: Record<string, string> = {
  resolves_to: "resolves to",
  cname_to: "CNAME",
  ns_for: "NS",
  mx_for: "MX",
  redirects_to: "redirects",
  cert_covers: "cert covers",
  hosts: "hosts",
};

const MIN_NODE_RADIUS = 8;
const MAX_NODE_RADIUS = 30;

// Label visibility zoom thresholds
const ZOOM_LABELS_IMPORTANT = 0.6; // Show labels for high-risk/domain nodes
const ZOOM_LABELS_ALL = 1.4; // Show all node labels
const ZOOM_EDGE_LABELS = 2.2; // Show edge relationship labels

// ------------------------------------------------------------------ store
const graphStore = useGraphStore();

// ------------------------------------------------------------------ refs
const svgContainer = ref<HTMLDivElement | null>(null);
const searchQuery = ref("");
const searchResults = ref<GraphNode[]>([]);
const showSearchResults = ref(false);
const selectedNode = ref<GraphNode | null>(null);
const showStatsPanel = ref(false);

// Current zoom scale for label visibility
const currentZoomScale = ref(1);

// Node type visibility filters
const visibleTypes = ref<Set<AssetNodeType>>(
  new Set(["domain", "subdomain", "ip", "service", "url"]),
);

function toggleTypeFilter(type: AssetNodeType): void {
  if (visibleTypes.value.has(type)) {
    // Don't allow hiding all types
    if (visibleTypes.value.size > 1) {
      visibleTypes.value.delete(type);
    }
  } else {
    visibleTypes.value.add(type);
  }
  updateVisibility();
}

function showAllTypes(): void {
  visibleTypes.value = new Set(["domain", "subdomain", "ip", "service", "url"]);
  updateVisibility();
}

// Tooltip state
const tooltip = ref({
  visible: false,
  x: 0,
  y: 0,
  node: null as GraphNode | null,
});

// D3 objects (not reactive, managed outside Vue reactivity)
let svg: Selection<SVGSVGElement, unknown, null, undefined> | null = null;
let svgGroup: Selection<SVGGElement, unknown, null, undefined> | null = null;
let simulation: Simulation<GraphNode, SimulationEdge> | null = null;
let zoomBehavior: ZoomBehavior<SVGSVGElement, unknown> | null = null;
let linkGroup: Selection<SVGGElement, unknown, null, undefined> | null = null;
let nodeGroup: Selection<SVGGElement, unknown, null, undefined> | null = null;
let labelGroup: Selection<SVGGElement, unknown, null, undefined> | null = null;

// ------------------------------------------------------------------ computed
const isLoading = computed(
  () => graphStore.isLoadingNodes || graphStore.isLoadingEdges,
);
const isExpanding = computed(() => graphStore.isExpandingNode);

const isDarkMode = computed(
  () =>
    typeof document !== "undefined" &&
    document.documentElement.classList.contains("dark"),
);

const colorMap = computed(() =>
  isDarkMode.value ? NODE_COLORS_DARK : NODE_COLORS,
);

const statsHighestRisk = computed(() => {
  const node = graphStore.highestRiskNode;
  if (!node) return "N/A";
  return `${node.identifier} (${node.risk_score})`;
});

// ------------------------------------------------------------------ helpers
function nodeRadius(riskScore: number): number {
  // Clamp risk_score to 0-100 then linearly map to radius range
  const clamped = Math.max(0, Math.min(100, riskScore));
  return (
    MIN_NODE_RADIUS + (clamped / 100) * (MAX_NODE_RADIUS - MIN_NODE_RADIUS)
  );
}

function nodeColor(type: AssetNodeType): string {
  return colorMap.value[type] || colorMap.value.domain;
}

function edgeLabel(relType: string): string {
  return REL_TYPE_LABELS[relType] || relType;
}

// ------------------------------------------------------------------ D3 setup
function initializeSvg(): void {
  if (!svgContainer.value) return;

  const container = svgContainer.value;
  const width = container.clientWidth;
  const height = container.clientHeight;

  // Clear any existing SVG
  select(container).select("svg").remove();

  svg = select(container)
    .append("svg")
    .attr("width", "100%")
    .attr("height", "100%")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .attr("class", "surface-map-svg");

  svg.append("title").text("Attack Surface Map");

  // Define arrow markers for directed edges
  const defs = svg.append("defs");

  defs
    .append("marker")
    .attr("id", "arrowhead")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 20)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", isDarkMode.value ? "#64748b" : "#94a3b8");

  // Zoom group
  svgGroup = svg.append("g").attr("class", "zoom-group");

  // Layer ordering: edges behind nodes behind labels
  linkGroup = svgGroup.append("g").attr("class", "links");
  nodeGroup = svgGroup.append("g").attr("class", "nodes");
  labelGroup = svgGroup.append("g").attr("class", "labels");

  // Zoom and pan
  zoomBehavior = zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.1, 8])
    .on("zoom", (event: D3ZoomEvent<SVGSVGElement, unknown>) => {
      svgGroup!.attr("transform", event.transform.toString());
      currentZoomScale.value = event.transform.k;
      updateLabelVisibility();
    });

  svg.call(zoomBehavior);

  // Center the initial view
  const initialTransform = zoomIdentity.translate(width / 2, height / 2);
  svg.call(zoomBehavior.transform, initialTransform);
}

function buildSimulation(): void {
  if (!svgContainer.value) return;

  // Deep-copy nodes so D3 can mutate x/y/vx/vy freely
  const simNodes: GraphNode[] = graphStore.nodes.map((n) => ({ ...n }));

  // Build edges referencing node ids (D3 will resolve them from the nodes array)
  // Filter out edges that reference nodes not in the loaded set to prevent
  // D3 forceLink "node not found" crashes (API may return limited nodes)
  const nodeIdSet = new Set(simNodes.map((n) => n.id));
  const simEdges: SimulationEdge[] = graphStore.simulationEdges
    .filter((e) => nodeIdSet.has(e.source) && nodeIdSet.has(e.target))
    .map((e) => ({ ...e }));

  // Adaptive force parameters based on graph size
  const nodeCount = simNodes.length;
  const chargeStrength = nodeCount > 500 ? -150 : nodeCount > 200 ? -250 : -300;
  const linkDistance = nodeCount > 500 ? 80 : nodeCount > 200 ? 100 : 120;
  const linkStrength = nodeCount > 500 ? 0.2 : 0.4;
  const alphaDecay = nodeCount > 500 ? 0.03 : 0.02;

  // Create the force simulation
  simulation = forceSimulation<GraphNode, SimulationEdge>(simNodes)
    .force(
      "link",
      forceLink<GraphNode, SimulationEdge>(simEdges)
        .id((d) => d.id)
        .distance(linkDistance)
        .strength(linkStrength),
    )
    .force("charge", forceManyBody().strength(chargeStrength).distanceMax(600))
    .force("center", forceCenter(0, 0))
    .force(
      "collision",
      forceCollide<GraphNode>().radius((d) => nodeRadius(d.risk_score) + 2),
    )
    .alphaDecay(alphaDecay)
    .on("tick", ticked);

  renderGraph(simNodes, simEdges);
}

// ------------------------------------------------------------------ label & filter visibility
function shouldShowLabel(d: GraphNode): boolean {
  const scale = currentZoomScale.value;
  if (scale >= ZOOM_LABELS_ALL) return true;
  if (scale >= ZOOM_LABELS_IMPORTANT) {
    // Show labels only for domains and high-risk nodes
    return d.type === "domain" || d.risk_score >= 60;
  }
  return false;
}

function updateLabelVisibility(): void {
  if (!labelGroup || !nodeGroup) return;

  const scale = currentZoomScale.value;

  // Node labels: visibility based on zoom
  labelGroup
    .selectAll<SVGTextElement, GraphNode>(".node-label")
    .attr("display", (d) => (shouldShowLabel(d) ? null : "none"));

  // Edge labels: only at high zoom
  labelGroup
    .selectAll<SVGTextElement, SimulationEdge>(".edge-label")
    .attr("display", scale >= ZOOM_EDGE_LABELS ? null : "none");
}

function updateVisibility(): void {
  if (!nodeGroup || !linkGroup || !labelGroup) return;

  // Toggle node visibility based on type filter
  nodeGroup
    .selectAll<SVGCircleElement, GraphNode>("circle")
    .attr("display", (d) => (visibleTypes.value.has(d.type) ? null : "none"));

  // Hide labels for hidden nodes
  labelGroup
    .selectAll<SVGTextElement, GraphNode>(".node-label")
    .attr("display", (d) =>
      visibleTypes.value.has(d.type) && shouldShowLabel(d) ? null : "none",
    );

  // Hide edges connected to hidden nodes
  const hiddenNodeIds = new Set(
    (simulation?.nodes() ?? [])
      .filter((n) => !visibleTypes.value.has(n.type))
      .map((n) => n.id),
  );

  linkGroup
    .selectAll<SVGLineElement, SimulationEdge>("line")
    .attr("display", (d) => {
      const srcId = getSourceId(d);
      const tgtId = getTargetId(d);
      return hiddenNodeIds.has(srcId) || hiddenNodeIds.has(tgtId)
        ? "none"
        : null;
    });

  labelGroup
    .selectAll<SVGTextElement, SimulationEdge>(".edge-label")
    .attr("display", (d) => {
      if (currentZoomScale.value < ZOOM_EDGE_LABELS) return "none";
      const srcId = getSourceId(d);
      const tgtId = getTargetId(d);
      return hiddenNodeIds.has(srcId) || hiddenNodeIds.has(tgtId)
        ? "none"
        : null;
    });
}

function renderGraph(simNodes: GraphNode[], simEdges: SimulationEdge[]): void {
  if (!linkGroup || !nodeGroup || !labelGroup) return;

  const dark = isDarkMode.value;
  const edgeColor = dark ? "#475569" : "#cbd5e1";
  const edgeLabelColor = dark ? "#94a3b8" : "#64748b";
  const textColor = dark ? "#e2e8f0" : "#1e293b";

  // --- Edges ---
  const links = linkGroup
    .selectAll<SVGLineElement, SimulationEdge>("line")
    .data(simEdges, (d) => `${getSourceId(d)}-${getTargetId(d)}-${d.rel_type}`);

  links.exit().remove();

  const linksEnter = links
    .enter()
    .append("line")
    .attr("stroke", edgeColor)
    .attr("stroke-width", 1.5)
    .attr("stroke-opacity", 0.6)
    .attr("marker-end", "url(#arrowhead)");

  linksEnter.merge(links);

  // --- Edge labels (hidden by default, visible at high zoom) ---
  const edgeLabels = labelGroup
    .selectAll<SVGTextElement, SimulationEdge>(".edge-label")
    .data(simEdges, (d) => `${getSourceId(d)}-${getTargetId(d)}-${d.rel_type}`);

  edgeLabels.exit().remove();

  const edgeLabelsEnter = edgeLabels
    .enter()
    .append("text")
    .attr("class", "edge-label")
    .attr("text-anchor", "middle")
    .attr("font-size", "9px")
    .attr("fill", edgeLabelColor)
    .attr("pointer-events", "none")
    .attr("display", "none")
    .text((d) => edgeLabel(d.rel_type));

  edgeLabelsEnter.merge(edgeLabels);

  // --- Nodes ---
  const nodeEls = nodeGroup
    .selectAll<SVGCircleElement, GraphNode>("circle")
    .data(simNodes, (d) => d.id);

  nodeEls.exit().remove();

  const nodeEnter = nodeEls
    .enter()
    .append("circle")
    .attr("r", (d) => nodeRadius(d.risk_score))
    .attr("fill", (d) => nodeColor(d.type))
    .attr("stroke", dark ? "#1e293b" : "#ffffff")
    .attr("stroke-width", 2)
    .attr("cursor", "pointer")
    .on("mouseover", handleNodeMouseOver)
    .on("mousemove", handleNodeMouseMove)
    .on("mouseout", handleNodeMouseOut)
    .on("click", handleNodeClick)
    .call(
      drag<SVGCircleElement, GraphNode>()
        .on("start", dragStarted)
        .on("drag", dragged)
        .on("end", dragEnded),
    );

  nodeEnter.merge(nodeEls).attr("fill", (d) => nodeColor(d.type));

  // --- Node text labels (zoom-dependent visibility) ---
  const nodeLabels = labelGroup
    .selectAll<SVGTextElement, GraphNode>(".node-label")
    .data(simNodes, (d) => d.id);

  nodeLabels.exit().remove();

  const nodeLabelsEnter = nodeLabels
    .enter()
    .append("text")
    .attr("class", "node-label")
    .attr("text-anchor", "middle")
    .attr("dy", (d) => nodeRadius(d.risk_score) + 14)
    .attr("font-size", "10px")
    .attr("fill", textColor)
    .attr("pointer-events", "none")
    .attr("display", (d) => (shouldShowLabel(d) ? null : "none"))
    .text((d) => truncateLabel(d.identifier, 20));

  nodeLabelsEnter.merge(nodeLabels);
}

function ticked(): void {
  if (!linkGroup || !nodeGroup || !labelGroup) return;

  linkGroup
    .selectAll<SVGLineElement, SimulationEdge>("line")
    .attr("x1", (d) => getSourceX(d))
    .attr("y1", (d) => getSourceY(d))
    .attr("x2", (d) => getTargetX(d))
    .attr("y2", (d) => getTargetY(d));

  labelGroup
    .selectAll<SVGTextElement, SimulationEdge>(".edge-label")
    .attr("x", (d) => (getSourceX(d) + getTargetX(d)) / 2)
    .attr("y", (d) => (getSourceY(d) + getTargetY(d)) / 2 - 4);

  nodeGroup
    .selectAll<SVGCircleElement, GraphNode>("circle")
    .attr("cx", (d) => d.x ?? 0)
    .attr("cy", (d) => d.y ?? 0);

  labelGroup
    .selectAll<SVGTextElement, GraphNode>(".node-label")
    .attr("x", (d) => d.x ?? 0)
    .attr("y", (d) => d.y ?? 0);
}

// ------------------------------------------------------------------ helpers for D3 link accessors
// After D3 resolves force-link, source/target become node objects
function getSourceId(d: SimulationEdge): number {
  const src = d.source as unknown;
  if (typeof src === "object" && src !== null && "id" in src) {
    return (src as GraphNode).id;
  }
  return src as number;
}

function getTargetId(d: SimulationEdge): number {
  const tgt = d.target as unknown;
  if (typeof tgt === "object" && tgt !== null && "id" in tgt) {
    return (tgt as GraphNode).id;
  }
  return tgt as number;
}

function getSourceX(d: SimulationEdge): number {
  const src = d.source as unknown;
  if (typeof src === "object" && src !== null && "x" in src) {
    return (src as GraphNode).x ?? 0;
  }
  return 0;
}

function getSourceY(d: SimulationEdge): number {
  const src = d.source as unknown;
  if (typeof src === "object" && src !== null && "y" in src) {
    return (src as GraphNode).y ?? 0;
  }
  return 0;
}

function getTargetX(d: SimulationEdge): number {
  const tgt = d.target as unknown;
  if (typeof tgt === "object" && tgt !== null && "x" in tgt) {
    return (tgt as GraphNode).x ?? 0;
  }
  return 0;
}

function getTargetY(d: SimulationEdge): number {
  const tgt = d.target as unknown;
  if (typeof tgt === "object" && tgt !== null && "y" in tgt) {
    return (tgt as GraphNode).y ?? 0;
  }
  return 0;
}

function truncateLabel(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.substring(0, max - 1) + "\u2026";
}

// ------------------------------------------------------------------ drag handlers
function dragStarted(
  event: D3DragEvent<SVGCircleElement, GraphNode, GraphNode>,
): void {
  if (!event.active) simulation?.alphaTarget(0.3).restart();
  event.subject.fx = event.subject.x;
  event.subject.fy = event.subject.y;
}

function dragged(
  event: D3DragEvent<SVGCircleElement, GraphNode, GraphNode>,
): void {
  event.subject.fx = event.x;
  event.subject.fy = event.y;
}

function dragEnded(
  event: D3DragEvent<SVGCircleElement, GraphNode, GraphNode>,
): void {
  if (!event.active) simulation?.alphaTarget(0);
  event.subject.fx = null;
  event.subject.fy = null;
}

// ------------------------------------------------------------------ interaction handlers
function handleNodeMouseOver(event: MouseEvent, d: GraphNode): void {
  tooltip.value = {
    visible: true,
    x: event.clientX,
    y: event.clientY,
    node: d,
  };

  // Highlight the hovered node
  select(event.currentTarget as SVGCircleElement)
    .attr("stroke-width", 4)
    .attr("stroke", "#facc15"); // yellow-400
}

function handleNodeMouseMove(event: MouseEvent): void {
  tooltip.value.x = event.clientX;
  tooltip.value.y = event.clientY;
}

function handleNodeMouseOut(event: MouseEvent): void {
  tooltip.value.visible = false;
  tooltip.value.node = null;

  const dark = isDarkMode.value;
  select(event.currentTarget as SVGCircleElement)
    .attr("stroke-width", 2)
    .attr("stroke", dark ? "#1e293b" : "#ffffff");
}

async function handleNodeClick(
  _event: MouseEvent,
  d: GraphNode,
): Promise<void> {
  selectedNode.value = d;
  await graphStore.expandNode(d.id);
  // Rebuild the simulation with the updated data
  rebuildGraph();
}

// ------------------------------------------------------------------ graph rebuild
function rebuildGraph(): void {
  if (simulation) {
    simulation.stop();
    simulation = null;
  }
  buildSimulation();
}

// ------------------------------------------------------------------ search
function handleSearchInput(): void {
  if (!searchQuery.value.trim()) {
    searchResults.value = [];
    showSearchResults.value = false;
    return;
  }
  searchResults.value = graphStore.searchNodes(searchQuery.value, 8);
  showSearchResults.value = searchResults.value.length > 0;
}

function selectSearchResult(node: GraphNode): void {
  searchQuery.value = node.identifier;
  showSearchResults.value = false;
  searchResults.value = [];
  centerOnNode(node);
}

function handleSearchSubmit(): void {
  showSearchResults.value = false;
  const found = graphStore.findNodeByIdentifier(searchQuery.value);
  if (found) {
    centerOnNode(found);
  }
}

function handleSearchBlur(): void {
  setTimeout(() => {
    showSearchResults.value = false;
  }, 200);
}

function centerOnNode(target: GraphNode): void {
  if (!svg || !zoomBehavior || !svgContainer.value) return;

  // Find the simulation node with matching id to get current x/y
  const simNode = simulation?.nodes().find((n) => n.id === target.id);
  if (!simNode || simNode.x == null || simNode.y == null) return;

  const width = svgContainer.value.clientWidth;
  const height = svgContainer.value.clientHeight;

  const transform = zoomIdentity
    .translate(width / 2, height / 2)
    .scale(1.5)
    .translate(-simNode.x, -simNode.y);

  svg.transition().duration(750).call(zoomBehavior.transform, transform);

  // Briefly highlight the node
  selectedNode.value = target;
  nodeGroup
    ?.selectAll<SVGCircleElement, GraphNode>("circle")
    .attr("stroke-width", (d) => (d.id === target.id ? 4 : 2))
    .attr("stroke", (d) =>
      d.id === target.id ? "#facc15" : isDarkMode.value ? "#1e293b" : "#ffffff",
    );

  // Reset highlight after a moment
  setTimeout(() => {
    nodeGroup
      ?.selectAll<SVGCircleElement, GraphNode>("circle")
      .attr("stroke-width", 2)
      .attr("stroke", isDarkMode.value ? "#1e293b" : "#ffffff");
  }, 2000);
}

// ------------------------------------------------------------------ reset zoom
function resetZoom(): void {
  if (!svg || !zoomBehavior || !svgContainer.value) return;
  const width = svgContainer.value.clientWidth;
  const height = svgContainer.value.clientHeight;
  const transform = zoomIdentity.translate(width / 2, height / 2);
  svg.transition().duration(500).call(zoomBehavior.transform, transform);
}

// ------------------------------------------------------------------ lifecycle
onMounted(async () => {
  await graphStore.fetchGraph();
  await nextTick();
  initializeSvg();
  if (graphStore.nodes.length > 0) {
    buildSimulation();
  }
});

onBeforeUnmount(() => {
  if (simulation) {
    simulation.stop();
    simulation = null;
  }
});

// Re-render when dark mode changes (observed via MutationObserver)
let darkModeObserver: MutationObserver | null = null;

onMounted(() => {
  if (typeof document !== "undefined") {
    darkModeObserver = new MutationObserver(() => {
      // Re-render with updated colors when dark mode toggles
      if (simulation) {
        rebuildGraph();
      }
    });
    darkModeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
  }
});

onBeforeUnmount(() => {
  darkModeObserver?.disconnect();
});

// Watch for window resize
let resizeTimeout: ReturnType<typeof setTimeout> | null = null;

function handleResize(): void {
  if (resizeTimeout) clearTimeout(resizeTimeout);
  resizeTimeout = setTimeout(() => {
    initializeSvg();
    if (graphStore.nodes.length > 0) {
      buildSimulation();
    }
  }, 250);
}

onMounted(() => {
  window.addEventListener("resize", handleResize);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", handleResize);
  if (resizeTimeout) clearTimeout(resizeTimeout);
});

// Watch for store data changes triggered externally
watch(
  () => graphStore.nodes.length + graphStore.edges.length,
  (newVal, oldVal) => {
    // Only rebuild if something changed and we already have a simulation
    if (newVal !== oldVal && simulation && svgContainer.value) {
      rebuildGraph();
    }
  },
);
</script>

<template>
  <div
    class="relative h-full w-full flex flex-col bg-gray-50 dark:bg-dark-bg-primary"
  >
    <!-- Top Bar: search + stats -->
    <div
      class="flex items-center justify-between gap-4 px-4 py-3 bg-white dark:bg-dark-bg-secondary border-b border-gray-200 dark:border-dark-border z-10"
    >
      <!-- Search -->
      <div class="relative w-80">
        <div class="flex">
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search assets..."
            class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-dark-border rounded-l-md bg-white dark:bg-dark-bg-tertiary text-gray-900 dark:text-dark-text-primary placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
            @input="handleSearchInput"
            @keydown.enter="handleSearchSubmit"
            @focus="handleSearchInput"
            @blur="handleSearchBlur"
          />
          <button
            class="px-3 py-2 bg-primary-600 text-white text-sm font-medium rounded-r-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500"
            @click="handleSearchSubmit"
          >
            Find
          </button>
        </div>

        <!-- Search results dropdown -->
        <div
          v-if="showSearchResults && searchResults.length > 0"
          class="absolute top-full left-0 mt-1 w-full bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-md shadow-lg max-h-60 overflow-y-auto z-50"
        >
          <button
            v-for="result in searchResults"
            :key="result.id"
            class="w-full text-left px-3 py-2 text-sm hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary flex items-center gap-2"
            @mousedown.prevent="selectSearchResult(result)"
          >
            <span
              class="inline-block w-2.5 h-2.5 rounded-full flex-shrink-0"
              :style="{ backgroundColor: nodeColor(result.type) }"
            ></span>
            <span class="text-gray-900 dark:text-dark-text-primary truncate">
              {{ result.identifier }}
            </span>
            <span
              class="ml-auto text-xs text-gray-500 dark:text-dark-text-tertiary capitalize"
            >
              {{ result.type }}
            </span>
          </button>
        </div>
      </div>

      <!-- Type Filters -->
      <div class="flex items-center gap-1.5">
        <button
          v-for="item in LEGEND_ITEMS"
          :key="item.type"
          class="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-full border transition-all"
          :class="
            visibleTypes.has(item.type)
              ? 'border-transparent text-white'
              : 'border-gray-300 dark:border-dark-border text-gray-400 dark:text-gray-500 bg-transparent'
          "
          :style="
            visibleTypes.has(item.type)
              ? { backgroundColor: nodeColor(item.type) }
              : {}
          "
          @click="toggleTypeFilter(item.type)"
        >
          {{ item.label }}
        </button>
        <button
          v-if="visibleTypes.size < 5"
          class="px-2 py-1.5 text-xs text-primary-600 dark:text-primary-400 hover:underline"
          @click="showAllTypes"
        >
          Show all
        </button>
      </div>

      <!-- Stats bar -->
      <div class="flex items-center gap-4 text-sm">
        <div class="flex items-center gap-1.5">
          <span class="text-gray-500 dark:text-dark-text-secondary"
            >Nodes:</span
          >
          <span class="font-semibold text-gray-900 dark:text-dark-text-primary">
            {{ graphStore.totalNodes }}
          </span>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="text-gray-500 dark:text-dark-text-secondary"
            >Edges:</span
          >
          <span class="font-semibold text-gray-900 dark:text-dark-text-primary">
            {{ graphStore.totalEdges }}
          </span>
        </div>
        <div class="hidden lg:flex items-center gap-1.5">
          <span class="text-gray-500 dark:text-dark-text-secondary">Risk:</span>
          <span
            class="font-semibold text-severity-critical truncate max-w-[180px]"
          >
            {{ statsHighestRisk }}
          </span>
        </div>
        <button
          class="px-3 py-1.5 text-xs font-medium text-gray-700 dark:text-dark-text-secondary bg-gray-100 dark:bg-dark-bg-tertiary rounded hover:bg-gray-200 dark:hover:bg-gray-600"
          :class="{
            'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300':
              showStatsPanel,
          }"
          @click="showStatsPanel = !showStatsPanel"
        >
          Stats
        </button>
        <button
          class="px-3 py-1.5 text-xs font-medium text-gray-700 dark:text-dark-text-secondary bg-gray-100 dark:bg-dark-bg-tertiary rounded hover:bg-gray-200 dark:hover:bg-gray-600"
          @click="resetZoom"
        >
          Reset Zoom
        </button>
      </div>
    </div>

    <!-- Main SVG Canvas -->
    <div ref="svgContainer" class="flex-1 relative overflow-hidden">
      <!-- Loading overlay -->
      <div
        v-if="isLoading"
        class="absolute inset-0 flex items-center justify-center bg-gray-50/80 dark:bg-dark-bg-primary/80 z-20"
      >
        <div class="flex flex-col items-center gap-3">
          <div
            class="w-10 h-10 border-4 border-primary-200 border-t-primary-600 rounded-full animate-spin"
          ></div>
          <span class="text-sm text-gray-600 dark:text-dark-text-secondary">
            Loading attack surface graph...
          </span>
        </div>
      </div>

      <!-- Expanding node overlay -->
      <div
        v-if="isExpanding"
        class="absolute top-4 right-4 flex items-center gap-2 px-3 py-2 bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-md shadow-md z-20"
      >
        <div
          class="w-4 h-4 border-2 border-primary-200 border-t-primary-600 rounded-full animate-spin"
        ></div>
        <span class="text-xs text-gray-600 dark:text-dark-text-secondary"
          >Expanding node...</span
        >
      </div>

      <!-- Empty state -->
      <div
        v-if="!isLoading && graphStore.nodes.length === 0 && !graphStore.error"
        class="absolute inset-0 flex items-center justify-center z-10"
      >
        <div class="text-center">
          <svg
            aria-hidden="true"
            class="mx-auto w-16 h-16 text-gray-300 dark:text-gray-600"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="1.5"
              d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
            />
          </svg>
          <p class="mt-4 text-gray-500 dark:text-dark-text-secondary">
            No assets discovered yet.
          </p>
          <p class="mt-1 text-sm text-gray-400 dark:text-dark-text-tertiary">
            Run a scan to populate the attack surface graph.
          </p>
        </div>
      </div>

      <!-- Error state -->
      <div
        v-if="graphStore.error"
        class="absolute top-4 left-1/2 -translate-x-1/2 z-20"
      >
        <div
          class="flex items-center gap-2 px-4 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md"
        >
          <svg
            aria-hidden="true"
            class="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0"
            fill="currentColor"
            viewBox="0 0 20 20"
          >
            <path
              fill-rule="evenodd"
              d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
              clip-rule="evenodd"
            />
          </svg>
          <span class="text-sm text-red-800 dark:text-red-200">{{
            graphStore.error
          }}</span>
          <button
            class="ml-2 text-xs text-red-600 dark:text-red-400 underline hover:no-underline"
            @click="graphStore.clearError()"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>

    <!-- Stats Panel (bottom-right) -->
    <div
      v-if="showStatsPanel && graphStore.stats"
      class="absolute bottom-4 right-4 bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg shadow-md p-4 z-10 w-72 max-h-[60vh] overflow-y-auto"
    >
      <div class="flex items-center justify-between mb-3">
        <p
          class="text-xs font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider"
        >
          Graph Statistics
        </p>
        <button
          class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          @click="showStatsPanel = false"
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
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      </div>

      <!-- Node counts by type -->
      <div class="mb-3">
        <p
          class="text-[11px] font-medium text-gray-500 dark:text-dark-text-tertiary mb-1.5"
        >
          Nodes by Type
        </p>
        <div class="space-y-1">
          <div
            v-for="(count, nodeType) in graphStore.stats.node_count_by_type"
            :key="'ntype-' + nodeType"
            class="flex items-center justify-between text-xs"
          >
            <div class="flex items-center gap-1.5">
              <span
                class="w-2.5 h-2.5 rounded-full"
                :style="{
                  backgroundColor: nodeColor(
                    nodeType as string as AssetNodeType,
                  ),
                }"
              ></span>
              <span
                class="text-gray-600 dark:text-dark-text-secondary capitalize"
                >{{ nodeType }}</span
              >
            </div>
            <span
              class="font-semibold text-gray-900 dark:text-dark-text-primary"
              >{{ count }}</span
            >
          </div>
        </div>
      </div>

      <!-- Edge counts by type -->
      <div class="mb-3 pt-2 border-t border-gray-100 dark:border-dark-border">
        <p
          class="text-[11px] font-medium text-gray-500 dark:text-dark-text-tertiary mb-1.5"
        >
          Edges by Type
        </p>
        <div class="space-y-1">
          <div
            v-for="(count, edgeType) in graphStore.stats.edge_count_by_type"
            :key="'etype-' + edgeType"
            class="flex items-center justify-between text-xs"
          >
            <span class="text-gray-600 dark:text-dark-text-secondary">{{
              edgeLabel(edgeType as string)
            }}</span>
            <span
              class="font-semibold text-gray-900 dark:text-dark-text-primary"
              >{{ count }}</span
            >
          </div>
        </div>
      </div>

      <!-- Most connected nodes -->
      <div
        v-if="graphStore.stats.most_connected.length > 0"
        class="pt-2 border-t border-gray-100 dark:border-dark-border"
      >
        <p
          class="text-[11px] font-medium text-gray-500 dark:text-dark-text-tertiary mb-1.5"
        >
          Most Connected
        </p>
        <div class="space-y-1.5">
          <div
            v-for="mc in graphStore.stats.most_connected.slice(0, 5)"
            :key="'mc-' + mc.id"
            class="flex items-center justify-between text-xs"
          >
            <div class="flex items-center gap-1.5 truncate mr-2">
              <span
                class="w-2 h-2 rounded-full flex-shrink-0"
                :style="{
                  backgroundColor: nodeColor(mc.type as AssetNodeType),
                }"
              ></span>
              <span
                class="text-gray-700 dark:text-dark-text-secondary truncate"
                >{{ mc.identifier }}</span
              >
            </div>
            <span
              class="font-semibold text-gray-900 dark:text-dark-text-primary flex-shrink-0"
              >{{ mc.connection_count }}</span
            >
          </div>
        </div>
      </div>
    </div>

    <!-- Legend (bottom-left) -->
    <div
      class="absolute bottom-4 left-4 bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg shadow-md p-3 z-10"
    >
      <p
        class="text-xs font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider mb-2"
      >
        Node Types
      </p>
      <div class="flex flex-col gap-1.5">
        <div
          v-for="item in LEGEND_ITEMS"
          :key="item.type"
          class="flex items-center gap-2"
        >
          <span
            class="inline-block w-3 h-3 rounded-full flex-shrink-0"
            :style="{ backgroundColor: nodeColor(item.type) }"
          ></span>
          <span class="text-xs text-gray-600 dark:text-dark-text-secondary">
            {{ item.label }}
          </span>
        </div>
      </div>
      <div
        class="mt-3 pt-2 border-t border-gray-100 dark:border-dark-border space-y-0.5"
      >
        <p class="text-[10px] text-gray-400 dark:text-dark-text-tertiary">
          Node size = risk score
        </p>
        <p class="text-[10px] text-gray-400 dark:text-dark-text-tertiary">
          Click node to expand neighbors
        </p>
        <p class="text-[10px] text-gray-400 dark:text-dark-text-tertiary">
          Zoom in to reveal labels
        </p>
      </div>
    </div>

    <!-- Tooltip -->
    <Teleport to="body">
      <div
        v-if="tooltip.visible && tooltip.node"
        class="fixed z-[9999] pointer-events-none"
        :style="{
          left: tooltip.x + 12 + 'px',
          top: tooltip.y - 10 + 'px',
        }"
      >
        <div
          class="bg-gray-900 dark:bg-gray-800 text-white text-xs rounded-lg shadow-lg px-3 py-2 max-w-xs"
        >
          <p class="font-semibold truncate">{{ tooltip.node.identifier }}</p>
          <div class="mt-1 space-y-0.5 text-gray-300">
            <p>
              <span class="text-gray-400">Type:</span>
              <span class="capitalize ml-1">{{ tooltip.node.type }}</span>
            </p>
            <p>
              <span class="text-gray-400">Risk Score:</span>
              <span
                class="ml-1 font-medium"
                :class="{
                  'text-red-400': tooltip.node.risk_score >= 80,
                  'text-orange-400':
                    tooltip.node.risk_score >= 60 &&
                    tooltip.node.risk_score < 80,
                  'text-yellow-400':
                    tooltip.node.risk_score >= 40 &&
                    tooltip.node.risk_score < 60,
                  'text-green-400': tooltip.node.risk_score < 40,
                }"
              >
                {{ tooltip.node.risk_score }}
              </span>
            </p>
            <p>
              <span class="text-gray-400">Findings:</span>
              <span class="ml-1">{{ tooltip.node.finding_count }}</span>
            </p>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
/* Ensure the SVG container fills the available space */
.surface-map-svg {
  display: block;
}
</style>
