<script setup>
import DynamicFilter from "./DynamicFilter.vue";
import { ref, onMounted, watch } from "vue";
import axios from "axios";

const data = ref([]);
const inc1 = ref("");
const inc2 = ref("");
const inc3 = ref("");
const ninc1 = ref("");
const ninc2 = ref("");
const ninc3 = ref("");

const filteroptions = ref({});
const year = ref(1641013200000);
const filters = ref([]);
const extrafilters = ref([]);
async function addfilter(item) {
  extrafilters.value.push(item);
  await fetchData();
}
async function removefilter(item) {
  extrafilters.value = extrafilters.value.filter((f) => f.id !== item.id);
  await fetchData();
}
async function updatefilter(item) {
  extrafilters.value = extrafilters.value.map((f) => {
    if (f.id === item.id) {
      return item;
    }
    return f;
  });
  await fetchData();
}

onMounted(async () => {
  await fetchData();
});
watch([year, inc1, inc2, inc3, ninc1, ninc2, ninc3, extrafilters], (val) => {
  fetchData();
});
async function fetchData() {
  data.value = [];
  filters.value = [
    {
      field: "CveMetadata.DateReserved",
      value: year.value.toString(),
      operator: "gt",
    },
    {
      field: "CveMetadata.DateReserved",
      value: (year.value + 31536000000).toString(),
      operator: "lt",
    },
  ];
  if (inc1.value) {
    filters.value.push({
      field: "Description",
      value: inc1.value,
      operator: "inc",
    });
  }
  if (inc2.value) {
    filters.value.push({
      field: "Description",
      value: inc2.value,
      operator: "inc",
    });
  }
  if (inc3.value) {
    filters.value.push({
      field: "Description",
      value: inc3.value,
      operator: "inc",
    });
  }
  if (ninc1.value) {
    filters.value.push({
      field: "Description",
      value: ninc1.value,
      operator: "ninc",
    });
  }
  if (ninc2.value) {
    filters.value.push({
      field: "Description",
      value: ninc2.value,
      operator: "ninc",
    });
  }
  if (ninc3.value) {
    filters.value.push({
      field: "Description",
      value: ninc3.value,
      operator: "ninc",
    });
  }
  if (extrafilters.value && extrafilters.value.length > 0) {
    extrafilters.value.forEach((f) => {
      filters.value.push({
        field: f.field,
        value: f.values,
        operator: f.operator,
      });
    });
  }

  const response = await axios.post("/api/cves", filters.value);
  data.value = response.data.cves;
  filteroptions.value = response.data.options;
  console.log(response.data.options);
}
</script>

<template>
  <n-flex vertical align="flex-start" justify="flex-start">
    <n-date-picker v-model:value="year" type="year" />
    <DynamicFilter
      :attributes="filteroptions"
      :filters="extrafilters"
      @addfilter="addfilter"
      @removefilter="removefilter"
      @updatefilter="updatefilter"
    />

    <n-flex>
      <n-flex vertical>
        <n-input v-model:value="inc1" placeholder="include text"></n-input>
        <n-input v-model:value="inc2" placeholder="include text"></n-input>
        <n-input v-model:value="inc3" placeholder="include text"></n-input>
      </n-flex>
      <n-flex vertical>
        <n-input v-model:value="ninc1" placeholder="exclude text"></n-input>
        <n-input v-model:value="ninc2" placeholder="exclude text"></n-input>
        <n-input v-model:value="ninc3" placeholder="exclude text"></n-input>
      </n-flex>
    </n-flex>
    <n-h3>Count: {{ data.length }}</n-h3>
    <n-card size="small" v-for="c in data" :title="c.cveMetadata.cveId">
      <p>{{ c.containers.cna.descriptions[0]?.value ?? "no description" }}</p>
      <div v-for="metric in c.containers.cna.metrics[0]" :key="metric">
        <n-tag v-for="(value, key) in metric" :key="key">
          {{ key }}: {{ value }}
        </n-tag>
      </div>
    </n-card>
  </n-flex>
</template>

<style scoped></style>
