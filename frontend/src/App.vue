<script setup>
import { ref, onMounted, computed, watch } from "vue";
import axios from "axios";
import {
  NLayout,
  NLayoutHeader,
  NLayoutContent,
  NCard,
  NDataTable,
  NInput,
  NSelect,
  NButton,
  NSpace,
  NModal,
  NDescriptions,
  NDescriptionsItem,
  NTag,
  NPagination,
  NStatistic,
  NGrid,
  NGi,
  NSpin,
  NInputNumber,
  NAlert,
  NDivider,
  NText,
  NH2,
  NH3,
  NCollapse,
  NCollapseItem,
  NTooltip,
} from "naive-ui";
import { Download } from "@vicons/carbon";

// State
const loading = ref(false);
const cves = ref([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(50);
const totalPages = ref(0);

// Filter state
const search = ref("");
const yearFilter = ref(null);
const vendorFilter = ref([]);  // Changed to array for multi-select
const productFilter = ref([]); // Changed to array for multi-select
const severityFilter = ref(null);
const cweFilter = ref(null);
const kevFilter = ref(null); // CISA KEV filter
const scoreMin = ref(null);
const scoreMax = ref(null);
const sortBy = ref("datePublished");
const sortDesc = ref(true);

// Filter options
const options = ref({
  vendors: [],
  products: [],
  severities: [],
  years: [],
  cwes: [],
  attackVectors: [],
});

// Searchable select options
const vendorOptions = ref([]);
const productOptions = ref([]);
const cweOptions = ref([]);
const vendorLoading = ref(false);
const productLoading = ref(false);
const cweLoading = ref(false);

// Modal state
const showModal = ref(false);
const selectedCve = ref(null);

// Stats
const stats = ref(null);

// Year counts for chart
const yearCounts = ref([]);

// Chart type selector
const chartType = ref("simple");
const chartTypeOptions = [
  { label: "Simple Bar", value: "simple" },
  { label: "Stacked by Severity", value: "stacked" },
];

// Debounce timer
let searchTimeout = null;
let vendorSearchTimeout = null;
let productSearchTimeout = null;
let cweSearchTimeout = null;

// Year options for select
const yearOptions = computed(() => {
  return options.value.years.map((y) => ({ label: String(y), value: y }));
});

const severityOptions = computed(() => {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  return order
    .filter((s) => options.value.severities.includes(s))
    .map((s) => ({ label: s, value: s }));
});

const kevOptions = [
  { label: "In CISA KEV", value: true },
  { label: "Not in KEV", value: false },
];

// Chart data computed
const chartMaxCount = computed(() => {
  if (yearCounts.value.length === 0) return 1;
  return Math.max(...yearCounts.value.map((y) => y.count), 1);
});

// Severity colors for stacked chart
const severityColors = {
  CRITICAL: "#d03050",
  HIGH: "#f0a020",
  MEDIUM: "#2080f0",
  LOW: "#18a058",
  NONE: "#909399",
};

// Severity order for consistent stacking (bottom to top)
const severityOrder = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

// Search functions for vendor/product/cwe
async function searchVendors(query) {
  clearTimeout(vendorSearchTimeout);
  vendorSearchTimeout = setTimeout(async () => {
    vendorLoading.value = true;
    try {
      const response = await axios.post("/api/options/search", {
        field: "vendor",
        search: query || "",
        limit: 100,
      });
      vendorOptions.value = response.data.map((v) => ({ label: v, value: v }));
    } catch (error) {
      console.error("Error searching vendors:", error);
    } finally {
      vendorLoading.value = false;
    }
  }, 200);
}

async function searchProducts(query) {
  clearTimeout(productSearchTimeout);
  productSearchTimeout = setTimeout(async () => {
    productLoading.value = true;
    try {
      const params = {
        field: "product",
        search: query || "",
        limit: 100,
      };
      // Filter products by selected vendors if any are chosen
      if (vendorFilter.value && vendorFilter.value.length > 0) {
        params.vendors = vendorFilter.value;
      }
      const response = await axios.post("/api/options/search", params);
      productOptions.value = response.data.map((v) => ({ label: v, value: v }));
    } catch (error) {
      console.error("Error searching products:", error);
    } finally {
      productLoading.value = false;
    }
  }, 200);
}

async function searchCWEs(query) {
  clearTimeout(cweSearchTimeout);
  cweSearchTimeout = setTimeout(async () => {
    cweLoading.value = true;
    try {
      const response = await axios.post("/api/options/search", {
        field: "cwe",
        search: query || "",
        limit: 100,
      });
      cweOptions.value = response.data.map((v) => ({ label: v, value: v }));
    } catch (error) {
      console.error("Error searching CWEs:", error);
    } finally {
      cweLoading.value = false;
    }
  }, 200);
}

// Initialize options on focus
function handleVendorFocus() {
  if (vendorOptions.value.length === 0) {
    searchVendors("");
  }
}

function handleProductFocus() {
  if (productOptions.value.length === 0) {
    searchProducts("");
  }
}

function handleCWEFocus() {
  if (cweOptions.value.length === 0) {
    searchCWEs("");
  }
}

// Affected products columns (for modal)
const affectedProductColumns = [
  {
    title: "Vendor",
    key: "vendor",
    width: 150,
    ellipsis: { tooltip: true },
  },
  {
    title: "Product",
    key: "product",
    width: 150,
    ellipsis: { tooltip: true },
  },
  {
    title: "Versions",
    key: "versions",
    ellipsis: { tooltip: true },
  },
];

// Table columns
const columns = [
  {
    title: "CVE ID",
    key: "id",
    width: 150,
    minWidth: 120,
    resizable: true,
    sorter: true,
    render(row) {
      return row.id;
    },
  },
  {
    title: "Year",
    key: "year",
    width: 80,
    minWidth: 60,
    resizable: true,
    sorter: true,
  },
  {
    title: "Vendor",
    key: "vendor",
    width: 180,
    minWidth: 100,
    resizable: true,
    sorter: true,
    render(row) {
      if (!row.vendor) return "-";
      return h(
        "span",
        {
          class: "clickable-cell",
          onClick: (e) => {
            e.stopPropagation();
            addVendorFilter(row.vendor);
          },
          title: `Click to filter by ${row.vendor}`,
        },
        row.vendor
      );
    },
  },
  {
    title: "Product",
    key: "product",
    width: 180,
    minWidth: 100,
    resizable: true,
    sorter: true,
    render(row) {
      if (!row.product) return "-";
      return h(
        "span",
        {
          class: "clickable-cell",
          onClick: (e) => {
            e.stopPropagation();
            addProductFilter(row.product);
          },
          title: `Click to filter by ${row.product}`,
        },
        row.product
      );
    },
  },
  {
    title: "#",
    key: "affectedCount",
    width: 50,
    minWidth: 40,
    resizable: true,
    render(row) {
      const count = row.affectedProducts?.length || 0;
      if (count <= 1) return "";
      // Build tooltip content showing all affected products
      const tooltipContent = row.affectedProducts
        .map((ap) => `${ap.vendor} / ${ap.product}`)
        .join("\n");
      return h(
        NTooltip,
        { placement: "left" },
        {
          trigger: () => h(NTag, { size: "tiny", type: "info", style: "cursor: help" }, () => count),
          default: () => h("pre", { style: "margin: 0; font-size: 12px; white-space: pre-wrap;" }, tooltipContent),
        }
      );
    },
  },
  {
    title: "Severity",
    key: "baseSeverity",
    width: 100,
    minWidth: 80,
    resizable: true,
    sorter: true,
    render(row) {
      const colors = {
        CRITICAL: "error",
        HIGH: "warning",
        MEDIUM: "info",
        LOW: "success",
      };
      if (!row.baseSeverity) return "-";
      return h(NTag, { type: colors[row.baseSeverity] || "default", size: "small" }, () => row.baseSeverity);
    },
  },
  {
    title: "Score",
    key: "baseScore",
    width: 80,
    minWidth: 60,
    resizable: true,
    sorter: true,
    render(row) {
      return row.baseScore > 0 ? row.baseScore.toFixed(1) : "-";
    },
  },
  {
    title: "KEV",
    key: "inKEV",
    width: 60,
    minWidth: 50,
    resizable: true,
    render(row) {
      if (!row.inKEV) return "";
      return h(NTag, { type: "error", size: "tiny" }, () => "KEV");
    },
  },
  {
    title: "Published",
    key: "datePublished",
    width: 110,
    minWidth: 90,
    resizable: true,
    sorter: true,
    render(row) {
      if (!row.datePublished) return "-";
      return new Date(row.datePublished).toLocaleDateString();
    },
  },
  {
    title: "Description",
    key: "description",
    minWidth: 200,
    resizable: true,
    ellipsis: { tooltip: true },
    render(row) {
      const desc = row.description || row.title || "-";
      return desc.length > 100 ? desc.substring(0, 100) + "..." : desc;
    },
  },
];

// Fetch CVEs
async function fetchCVEs() {
  loading.value = true;
  try {
    const params = {
      page: page.value,
      pageSize: pageSize.value,
      sortBy: sortBy.value,
      sortDesc: sortDesc.value,
    };

    if (search.value) params.search = search.value;
    if (yearFilter.value) params.year = yearFilter.value;
    if (vendorFilter.value && vendorFilter.value.length > 0) params.vendors = vendorFilter.value;
    if (productFilter.value && productFilter.value.length > 0) params.products = productFilter.value;
    if (severityFilter.value) params.severity = severityFilter.value;
    if (cweFilter.value) params.cwe = cweFilter.value;
    if (kevFilter.value !== null) params.inKEV = kevFilter.value;
    if (scoreMin.value !== null) params.scoreMin = scoreMin.value;
    if (scoreMax.value !== null) params.scoreMax = scoreMax.value;

    const response = await axios.post("/api/cves", params);
    cves.value = response.data.cves || [];
    total.value = response.data.total;
    totalPages.value = response.data.totalPages;
    options.value = response.data.options;
    yearCounts.value = response.data.yearCounts || [];
  } catch (error) {
    console.error("Error fetching CVEs:", error);
  } finally {
    loading.value = false;
  }
}

// Fetch stats
async function fetchStats() {
  try {
    const response = await axios.get("/api/stats");
    stats.value = response.data;
  } catch (error) {
    console.error("Error fetching stats:", error);
  }
}

// Export to XLS
async function exportToXLS() {
  try {
    const params = {
      sortBy: sortBy.value,
      sortDesc: sortDesc.value,
    };

    if (search.value) params.search = search.value;
    if (yearFilter.value) params.year = yearFilter.value;
    if (vendorFilter.value && vendorFilter.value.length > 0) params.vendors = vendorFilter.value;
    if (productFilter.value && productFilter.value.length > 0) params.products = productFilter.value;
    if (severityFilter.value) params.severity = severityFilter.value;
    if (cweFilter.value) params.cwe = cweFilter.value;
    if (kevFilter.value !== null) params.inKEV = kevFilter.value;
    if (scoreMin.value !== null) params.scoreMin = scoreMin.value;
    if (scoreMax.value !== null) params.scoreMax = scoreMax.value;

    const response = await axios.post("/api/export", params, {
      responseType: "blob",
    });

    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `cve_export_${new Date().toISOString().split("T")[0]}.xlsx`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error("Error exporting:", error);
  }
}

// Handle row click
function handleRowClick(row) {
  selectedCve.value = row;
  showModal.value = true;
}

// Add vendor to filter (from cell click)
function addVendorFilter(vendor) {
  if (!vendor) return;
  if (!vendorFilter.value.includes(vendor)) {
    vendorFilter.value = [...vendorFilter.value, vendor];
  }
}

// Add product to filter (from cell click)
function addProductFilter(product) {
  if (!product) return;
  if (!productFilter.value.includes(product)) {
    productFilter.value = [...productFilter.value, product];
  }
}

// Handle sort change
function handleSorterChange(sorter) {
  if (sorter && sorter.columnKey) {
    sortBy.value = sorter.columnKey;
    sortDesc.value = sorter.order === "descend";
  } else {
    sortBy.value = "datePublished";
    sortDesc.value = true;
  }
  fetchCVEs();
}

// Handle page change
function handlePageChange(newPage) {
  page.value = newPage;
  fetchCVEs();
}

// Handle page size change
function handlePageSizeChange(newSize) {
  pageSize.value = newSize;
  page.value = 1;
  fetchCVEs();
}

// Reset filters
function resetFilters() {
  search.value = "";
  yearFilter.value = null;
  vendorFilter.value = [];
  productFilter.value = [];
  severityFilter.value = null;
  cweFilter.value = null;
  kevFilter.value = null;
  scoreMin.value = null;
  scoreMax.value = null;
  page.value = 1;
  // Reload remote options to clear any search filters
  searchVendors("");
  searchProducts("");
  searchCWEs("");
  fetchCVEs();
}

// Watch for search changes with debounce
watch(search, () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    page.value = 1;
    fetchCVEs();
  }, 300);
});

// Watch for filter changes
watch(
  [yearFilter, productFilter, severityFilter, cweFilter, kevFilter, scoreMin, scoreMax],
  () => {
    page.value = 1;
    fetchCVEs();
  },
  { deep: true }
);

// Watch vendor filter separately to reload products when vendor changes
watch(vendorFilter, (newVendors, oldVendors) => {
  page.value = 1;
  // Clear product filter when vendors change significantly
  const oldLen = oldVendors?.length || 0;
  const newLen = newVendors?.length || 0;
  if (oldLen > 0 && newLen !== oldLen) {
    productFilter.value = [];
  }
  // Reload product options for the new vendor(s)
  searchProducts("");
  fetchCVEs();
}, { deep: true });

// Row props for double-click
function rowProps(row) {
  return {
    style: "cursor: pointer;",
    onDblclick: () => handleRowClick(row),
  };
}

// Severity color
function getSeverityType(severity) {
  const colors = {
    CRITICAL: "error",
    HIGH: "warning",
    MEDIUM: "info",
    LOW: "success",
  };
  return colors[severity] || "default";
}

// Initialize
onMounted(() => {
  fetchCVEs();
  fetchStats();
});

// h function for render
import { h } from "vue";
</script>

<template>
  <n-layout style="min-height: 100vh">
    <n-layout-header style="padding: 16px 24px; background: #fff; border-bottom: 1px solid #e8e8e8">
      <n-space justify="space-between" align="center">
        <n-h2 style="margin: 0">CVE Database Browser</n-h2>
        <n-space>
          <n-statistic v-if="stats" label="Total CVEs" :value="stats.totalCves.toLocaleString()" />
          <n-statistic v-if="total > 0" label="Filtered" :value="total.toLocaleString()" />
        </n-space>
      </n-space>
    </n-layout-header>

    <n-layout-content style="padding: 24px">
      <!-- Filters and Chart -->
      <n-grid :cols="3" :x-gap="16" style="margin-bottom: 16px">
        <n-gi :span="2">
          <n-card title="Filters" size="small">
            <n-space vertical>
              <n-grid :cols="6" :x-gap="12" :y-gap="12">
                <n-gi :span="2">
                  <n-input
                    v-model:value="search"
                    placeholder="Search CVE ID, description, vendor, product..."
                    clearable
                  />
                </n-gi>
                <n-gi>
                  <n-select
                    v-model:value="yearFilter"
                    :options="yearOptions"
                    placeholder="Year"
                    clearable
                  />
                </n-gi>
                <n-gi>
                  <n-select
                    v-model:value="vendorFilter"
                    :options="vendorOptions"
                    :loading="vendorLoading"
                    placeholder="Vendor(s)"
                    filterable
                    remote
                    clearable
                    multiple
                    max-tag-count="responsive"
                    clear-filter-after-select
                    :reset-menu-on-options-change="false"
                    @search="searchVendors"
                    @focus="handleVendorFocus"
                    @clear="() => { vendorFilter = []; searchVendors(''); }"
                  />
                </n-gi>
                <n-gi>
                  <n-select
                    v-model:value="productFilter"
                    :options="productOptions"
                    :loading="productLoading"
                    placeholder="Product(s)"
                    filterable
                    remote
                    clearable
                    multiple
                    max-tag-count="responsive"
                    clear-filter-after-select
                    :reset-menu-on-options-change="false"
                    @search="searchProducts"
                    @focus="handleProductFocus"
                    @clear="() => { productFilter = []; searchProducts(''); }"
                  />
                </n-gi>
                <n-gi>
                  <n-select
                    v-model:value="severityFilter"
                    :options="severityOptions"
                    placeholder="Severity"
                    clearable
                  />
                </n-gi>
              </n-grid>

              <n-grid :cols="6" :x-gap="12" :y-gap="12">
                <n-gi>
                  <n-select
                    v-model:value="cweFilter"
                    :options="cweOptions"
                    :loading="cweLoading"
                    placeholder="CWE (e.g., CWE-79)"
                    filterable
                    remote
                    clearable
                    clear-filter-after-select
                    :reset-menu-on-options-change="false"
                    @search="searchCWEs"
                    @focus="handleCWEFocus"
                    @clear="() => searchCWEs('')"
                  />
                </n-gi>
                <n-gi>
                  <n-select
                    v-model:value="kevFilter"
                    :options="kevOptions"
                    placeholder="CISA KEV"
                    clearable
                  />
                </n-gi>
                <n-gi>
                  <n-input-number
                    v-model:value="scoreMin"
                    placeholder="Min Score"
                    :min="0"
                    :max="10"
                    :step="0.1"
                    clearable
                    style="width: 100%"
                  />
                </n-gi>
                <n-gi>
                  <n-input-number
                    v-model:value="scoreMax"
                    placeholder="Max Score"
                    :min="0"
                    :max="10"
                    :step="0.1"
                    clearable
                    style="width: 100%"
                  />
                </n-gi>
                <n-gi>
                  <n-button @click="resetFilters" secondary>Reset Filters</n-button>
                </n-gi>
                <n-gi>
                  <n-button @click="exportToXLS" type="primary">
                    Export to Excel
                  </n-button>
                </n-gi>
              </n-grid>
            </n-space>
          </n-card>
        </n-gi>
        <n-gi>
          <n-card size="small" style="height: 100%">
            <template #header>
              <n-space justify="space-between" align="center" style="width: 100%">
                <span>CVEs by Year (Last 10 Years)</span>
                <n-select
                  v-model:value="chartType"
                  :options="chartTypeOptions"
                  size="tiny"
                  style="width: 140px"
                />
              </n-space>
            </template>
            <div class="year-chart" v-if="yearCounts.length > 0">
              <!-- Simple bar chart -->
              <div class="chart-bars" v-if="chartType === 'simple'">
                <div
                  v-for="item in yearCounts"
                  :key="item.year"
                  class="chart-bar-container"
                >
                  <span class="chart-count">{{ item.count > 0 ? item.count.toLocaleString() : '' }}</span>
                  <div
                    class="chart-bar"
                    :style="{ height: (item.count / chartMaxCount * 100) + '%' }"
                  ></div>
                  <span class="chart-label">{{ String(item.year).slice(-2) }}</span>
                </div>
              </div>
              <!-- Stacked bar chart by severity -->
              <div class="chart-bars" v-else-if="chartType === 'stacked'">
                <div
                  v-for="item in yearCounts"
                  :key="item.year"
                  class="chart-bar-container"
                >
                  <span class="chart-count">{{ item.count > 0 ? item.count.toLocaleString() : '' }}</span>
                  <n-tooltip placement="left" v-if="item.count > 0">
                    <template #trigger>
                      <div class="stacked-bar" :style="{ height: (item.count / chartMaxCount * 100) + '%' }">
                        <div
                          v-for="sev in severityOrder"
                          :key="sev"
                          class="stacked-segment"
                          :style="{
                            height: item.count > 0 ? ((item.severity?.[sev] || 0) / item.count * 100) + '%' : '0%',
                            backgroundColor: severityColors[sev],
                          }"
                        ></div>
                      </div>
                    </template>
                    <div class="severity-tooltip">
                      <div class="tooltip-title">{{ item.year }}</div>
                      <div v-for="sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']" :key="sev" class="tooltip-row">
                        <span class="tooltip-color" :style="{ backgroundColor: severityColors[sev] }"></span>
                        <span class="tooltip-label">{{ sev }}:</span>
                        <span class="tooltip-value">{{ (item.severity?.[sev] || 0).toLocaleString() }}</span>
                      </div>
                      <div class="tooltip-total">Total: {{ item.count.toLocaleString() }}</div>
                    </div>
                  </n-tooltip>
                  <div v-else class="stacked-bar" :style="{ height: '0%' }"></div>
                  <span class="chart-label">{{ String(item.year).slice(-2) }}</span>
                </div>
              </div>
            </div>
            <n-text v-else depth="3" style="display: block; text-align: center; padding: 20px;">
              No data
            </n-text>
            <!-- Legend for stacked chart -->
            <div v-if="chartType === 'stacked'" class="chart-legend">
              <span v-for="sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']" :key="sev" class="legend-item">
                <span class="legend-color" :style="{ backgroundColor: severityColors[sev] }"></span>
                <span class="legend-text">{{ sev }}</span>
              </span>
            </div>
          </n-card>
        </n-gi>
      </n-grid>

      <!-- Results info -->
      <n-space justify="space-between" align="center" style="margin-bottom: 12px">
        <n-text>
          Showing {{ cves.length }} of {{ total.toLocaleString() }} results
          <span v-if="total > 10000" style="color: #999"> (export limited to 10,000 rows)</span>
        </n-text>
        <n-text depth="3">Double-click a row to view details</n-text>
      </n-space>

      <!-- Data Table -->
      <n-spin :show="loading">
        <n-data-table
          :columns="columns"
          :data="cves"
          :row-props="rowProps"
          :bordered="false"
          :single-line="false"
          :scroll-x="1200"
          @update:sorter="handleSorterChange"
          size="small"
          striped
        />
      </n-spin>

      <!-- Pagination -->
      <n-space justify="center" style="margin-top: 16px">
        <n-pagination
          v-model:page="page"
          :page-count="totalPages"
          :page-size="pageSize"
          :page-sizes="[25, 50, 100, 200]"
          show-size-picker
          @update:page="handlePageChange"
          @update:page-size="handlePageSizeChange"
        />
      </n-space>
    </n-layout-content>

    <!-- CVE Detail Modal -->
    <n-modal
      v-model:show="showModal"
      preset="card"
      :title="selectedCve?.id || 'CVE Details'"
      style="width: 800px; max-width: 90vw"
      :bordered="false"
    >
      <template v-if="selectedCve">
        <n-space vertical>
          <!-- Severity and Score -->
          <n-space>
            <n-tag :type="getSeverityType(selectedCve.baseSeverity)" size="large" v-if="selectedCve.baseSeverity">
              {{ selectedCve.baseSeverity }}
            </n-tag>
            <n-tag v-if="selectedCve.baseScore > 0" size="large">
              Score: {{ selectedCve.baseScore.toFixed(1) }}
            </n-tag>
            <n-tag v-if="selectedCve.cwe" size="large" type="info">
              {{ selectedCve.cwe }}
            </n-tag>
            <n-tag v-if="selectedCve.inKEV" size="large" type="error">
              CISA KEV
            </n-tag>
          </n-space>

          <!-- CISA KEV Details -->
          <n-alert v-if="selectedCve.inKEV" type="error" title="CISA Known Exploited Vulnerability" style="margin-top: 12px">
            <n-descriptions :column="2" label-placement="left" size="small">
              <n-descriptions-item label="Date Added">{{ selectedCve.kevDateAdded || '-' }}</n-descriptions-item>
              <n-descriptions-item label="Due Date">{{ selectedCve.kevDueDate || '-' }}</n-descriptions-item>
              <n-descriptions-item label="Ransomware Use">
                <n-tag :type="selectedCve.kevKnownRansomwareCampaign === 'Known' ? 'error' : 'default'" size="small">
                  {{ selectedCve.kevKnownRansomwareCampaign || 'Unknown' }}
                </n-tag>
              </n-descriptions-item>
            </n-descriptions>
            <div v-if="selectedCve.kevRequiredAction" style="margin-top: 8px">
              <n-text strong>Required Action: </n-text>
              <n-text>{{ selectedCve.kevRequiredAction }}</n-text>
            </div>
          </n-alert>

          <n-divider />

          <!-- Description -->
          <div v-if="selectedCve.title">
            <n-h3 style="margin: 0 0 8px 0">Title</n-h3>
            <n-text>{{ selectedCve.title }}</n-text>
          </div>

          <div v-if="selectedCve.description">
            <n-h3 style="margin: 16px 0 8px 0">Description</n-h3>
            <n-text style="white-space: pre-wrap">{{ selectedCve.description }}</n-text>
          </div>

          <n-divider />

          <!-- Details -->
          <n-descriptions :column="2" label-placement="left" bordered>
            <n-descriptions-item label="CVE ID">{{ selectedCve.id }}</n-descriptions-item>
            <n-descriptions-item label="State">{{ selectedCve.state }}</n-descriptions-item>
            <n-descriptions-item label="Published">
              {{ selectedCve.datePublished ? new Date(selectedCve.datePublished).toLocaleDateString() : '-' }}
            </n-descriptions-item>
            <n-descriptions-item label="Updated">
              {{ selectedCve.dateUpdated ? new Date(selectedCve.dateUpdated).toLocaleDateString() : '-' }}
            </n-descriptions-item>
            <n-descriptions-item label="Assigner">{{ selectedCve.assignerOrg || '-' }}</n-descriptions-item>
          </n-descriptions>

          <!-- Affected Products -->
          <div v-if="selectedCve.affectedProducts && selectedCve.affectedProducts.length > 0">
            <n-h3 style="margin: 16px 0 8px 0">
              Affected Products
              <n-tag v-if="selectedCve.affectedProducts.length > 1" size="small" type="info" style="margin-left: 8px">
                {{ selectedCve.affectedProducts.length }} products
              </n-tag>
            </n-h3>
            <n-data-table
              :columns="affectedProductColumns"
              :data="selectedCve.affectedProducts"
              :bordered="true"
              :single-line="false"
              size="small"
              :max-height="200"
            />
          </div>
          <div v-else-if="selectedCve.vendor || selectedCve.product">
            <n-h3 style="margin: 16px 0 8px 0">Affected Product</n-h3>
            <n-descriptions :column="1" label-placement="left" bordered size="small">
              <n-descriptions-item label="Vendor">{{ selectedCve.vendor || '-' }}</n-descriptions-item>
              <n-descriptions-item label="Product">{{ selectedCve.product || '-' }}</n-descriptions-item>
              <n-descriptions-item label="Versions">{{ selectedCve.versions || '-' }}</n-descriptions-item>
            </n-descriptions>
          </div>

          <!-- CVSS Details -->
          <n-collapse v-if="selectedCve.vectorString">
            <n-collapse-item title="CVSS Details" name="cvss">
              <n-descriptions :column="2" label-placement="left" size="small">
                <n-descriptions-item label="Vector">{{ selectedCve.vectorString }}</n-descriptions-item>
                <n-descriptions-item label="Version">{{ selectedCve.cvssVersion }}</n-descriptions-item>
                <n-descriptions-item label="Attack Vector">{{ selectedCve.attackVector || '-' }}</n-descriptions-item>
                <n-descriptions-item label="Attack Complexity">{{ selectedCve.attackComplexity || '-' }}</n-descriptions-item>
                <n-descriptions-item label="Privileges Required">{{ selectedCve.privilegesRequired || '-' }}</n-descriptions-item>
                <n-descriptions-item label="User Interaction">{{ selectedCve.userInteraction || '-' }}</n-descriptions-item>
                <n-descriptions-item label="Scope">{{ selectedCve.scope || '-' }}</n-descriptions-item>
                <n-descriptions-item label="Confidentiality">{{ selectedCve.confidentialityImpact || '-' }}</n-descriptions-item>
                <n-descriptions-item label="Integrity">{{ selectedCve.integrityImpact || '-' }}</n-descriptions-item>
                <n-descriptions-item label="Availability">{{ selectedCve.availabilityImpact || '-' }}</n-descriptions-item>
              </n-descriptions>
            </n-collapse-item>
          </n-collapse>

          <!-- References -->
          <div v-if="selectedCve.references && selectedCve.references.length > 0">
            <n-h3 style="margin: 16px 0 8px 0">References</n-h3>
            <n-space vertical>
              <div v-for="(ref, index) in selectedCve.references" :key="index">
                <a :href="ref.url" target="_blank" rel="noopener noreferrer" style="word-break: break-all">
                  {{ ref.url }}
                </a>
                <n-space style="margin-top: 4px" v-if="ref.tags && ref.tags.length">
                  <n-tag v-for="tag in ref.tags" :key="tag" size="tiny" type="info">{{ tag }}</n-tag>
                </n-space>
              </div>
            </n-space>
          </div>
        </n-space>
      </template>
    </n-modal>
  </n-layout>
</template>

<style>
body {
  margin: 0;
  background: #f5f5f5;
}

.year-chart {
  height: 100px;
  display: flex;
  flex-direction: column;
}

.chart-bars {
  flex: 1;
  display: flex;
  align-items: flex-end;
  gap: 4px;
  padding-bottom: 4px;
}

.chart-bar-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  height: 100%;
  justify-content: flex-end;
}

.chart-count {
  font-size: 9px;
  color: #666;
  margin-bottom: 2px;
  white-space: nowrap;
}

.chart-bar {
  width: 100%;
  background: linear-gradient(to top, #4472C4, #6B8DD6);
  border-radius: 2px 2px 0 0;
  min-height: 2px;
  transition: height 0.3s ease;
  cursor: pointer;
}

.chart-bar:hover {
  background: linear-gradient(to top, #3461b3, #5a7cc5);
}

.chart-label {
  font-size: 10px;
  color: #666;
  margin-top: 4px;
}

.clickable-cell {
  cursor: pointer;
  color: inherit;
  text-overflow: ellipsis;
  overflow: hidden;
  white-space: nowrap;
  display: block;
}

.clickable-cell:hover {
  color: #4472C4;
  text-decoration: underline;
}

/* Stacked bar chart styles */
.stacked-bar {
  width: 100%;
  display: flex;
  flex-direction: column;
  border-radius: 2px 2px 0 0;
  overflow: hidden;
  min-height: 2px;
}

.stacked-segment {
  width: 100%;
  transition: height 0.3s ease;
  cursor: pointer;
}

.stacked-segment:hover {
  filter: brightness(1.1);
}

/* Chart legend */
.chart-legend {
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 8px;
  flex-wrap: wrap;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 10px;
}

.legend-color {
  width: 10px;
  height: 10px;
  border-radius: 2px;
}

.legend-text {
  color: #666;
}

/* Severity tooltip styles */
.severity-tooltip {
  font-size: 12px;
  min-width: 120px;
}

.tooltip-title {
  font-weight: bold;
  margin-bottom: 6px;
  padding-bottom: 4px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.2);
}

.tooltip-row {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 3px 0;
}

.tooltip-color {
  width: 10px;
  height: 10px;
  border-radius: 2px;
  flex-shrink: 0;
}

.tooltip-label {
  flex: 1;
}

.tooltip-value {
  font-weight: 500;
  text-align: right;
}

.tooltip-total {
  margin-top: 6px;
  padding-top: 4px;
  border-top: 1px solid rgba(255, 255, 255, 0.2);
  font-weight: bold;
}
</style>
