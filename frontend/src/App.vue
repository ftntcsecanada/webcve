<script setup>
import { ref, onMounted, watch } from "vue";
import axios from "axios";

const data = ref([]);
const inc1 = ref("");
const inc2 = ref("");
const inc3 = ref("");
const ninc1 = ref("");
const ninc2 = ref("");
const ninc3 = ref("");

const year = ref(1641013200000);
let filters = [];
onMounted(async () => {
  await fetchData();
});
watch([year, inc1, inc2, inc3, ninc1, ninc2, ninc3], (val) => {
  fetchData();
});
async function fetchData() {
  filters = [
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
    filters.push({
      field: "Description",
      value: inc1.value,
      operator: "inc",
    });
  }
  if (inc2.value) {
    filters.push({
      field: "Description",
      value: inc2.value,
      operator: "inc",
    });
  }
  if (inc3.value) {
    filters.push({
      field: "Description",
      value: inc3.value,
      operator: "inc",
    });
  }
  if (ninc1.value) {
    filters.push({
      field: "Description",
      value: ninc1.value,
      operator: "ninc",
    });
  }
  if (ninc2.value) {
    filters.push({
      field: "Description",
      value: ninc2.value,
      operator: "ninc",
    });
  }
  if (ninc3.value) {
    filters.push({
      field: "Description",
      value: ninc3.value,
      operator: "ninc",
    });
  }

  const response = await axios.post("/api/cves", filters);
  data.value = response.data;
}
</script>

<template>
  <n-flex>
    <n-date-picker v-model:value="year" type="year" />
    <n-input v-model:value="inc1" placeholder="include text"></n-input>
    <n-input v-model:value="inc2" placeholder="include text"></n-input>
    <n-input v-model:value="inc3" placeholder="include text"></n-input>
    <n-input v-model:value="ninc1" placeholder="exclude text"></n-input>
    <n-input v-model:value="ninc2" placeholder="exclude text"></n-input>
    <n-input v-model:value="ninc3" placeholder="exclude text"></n-input>
  </n-flex>

  <main>
    <n-flex vertical>
      <n-flex>
        <n-h3>Count: {{ data.length }}</n-h3>
        <n-h3>Filters:</n-h3>
        <n-flex vertical>
          <n-tag v-for="f in filters" :key="f.field">
            {{ f.field }} : <b>{{ f.operator }}</b> : {{ f.value }}
          </n-tag>
        </n-flex>
      </n-flex>
      <n-card size="small" v-for="c in data" :title="c.cveMetadata.cveId">
        <p>{{ c.containers.cna.descriptions[0]?.value ?? "no description" }}</p>
        <div v-for="metric in c.containers.cna.metrics[0]" :key="metric">
          <n-tag v-for="(value, key) in metric" :key="key">
            {{ key }}: {{ value }}
          </n-tag>
        </div>
      </n-card>
    </n-flex>
  </main>
</template>

<style scoped></style>
