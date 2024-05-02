<template>
  <!-- FilterMenu -->
  <n-modal
    v-model:show="showFilterMenu"
    :style="filterMenuStyle"
    class="filtermenu"
    @afterLeave="cleanup()"
  >
    <n-card
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
      content-style="padding:2px;"
    >
      <div class="filtermenu">
        <n-select
          class="filterattribute"
          v-model:value="filterfield"
          name="filterattribute"
          id="filterattribute"
          :options="fields"
          label-field="name"
          value-field="name"
          size="small"
          filterable
          default-value="name"
          :consistent-menu-width="false"
        />
        <n-button
          @click="
            filteroperator == 'eq'
              ? (filteroperator = 'neq')
              : (filteroperator = 'eq')
          "
          size="tiny"
          class="logicbutton"
          :type="filteroperator == 'eq' ? 'success' : 'error'"
          >{{ filteroperator == "eq" ? "=" : "!=" }}</n-button
        >
        <!-- If attribute is of type select -->
        <n-select
          v-model:value="attributevalueoption"
          name="attributevalueoptions"
          id="attributevalueoptions"
          :options="attributevalueoptionsnaive"
          class="filterattribute"
          filterable
          size="small"
          :consistent-menu-width="true"
        >
        </n-select>
        <!-- If attribute is of type string -->

        <n-button
          size="tiny"
          @click="addfilter()"
          class="iconbutton"
          type="info"
        >
          <template #icon>
            <n-icon :component="Add" />
          </template>
        </n-button>
        <n-button
          v-if="editeditem != null"
          size="tiny"
          @click="removefilter(editeditem)"
          class="iconbutton"
          type="info"
        >
          <template #icon>
            <n-icon :component="Delete" />
          </template>
        </n-button>
      </div>
    </n-card>
  </n-modal>

  <div class="filterbox">
    <!-- Existing filters -->

    <n-text>Filters:</n-text>
    <n-tag
      v-for="f in filterssorted"
      size="medium"
      closable
      @close="removefilter(f)"
      @click="editfilter(f)"
      :type="f.operator == 'eq' ? 'success' : 'error'"
      :class="
        editeditem != null && editeditem.id == f.id
          ? 'filtertextedit'
          : 'filtertext'
      "
      :ref="(el) => setFilterRef(el, f.id)"
    >
      <!-- <template #icon>
            <n-icon :component="Money16Regular" />
        </template> -->
      {{ f.field }} {{ f.operator == "eq" ? "=" : "!=" }} {{ f.values }}
    </n-tag>

    <!-- New filter -->
    <!-- <div class="filternew"> -->
    <div ref="refnewfilter">
      <n-button
        size="tiny"
        quaternary
        round
        @click="addNewFilter()"
        class="iconbutton"
        type="info"
      >
        <template #icon>
          <n-icon :component="Filter" />
        </template>
      </n-button>
    </div>
  </div>
</template>

<script setup>
import { watch, ref, computed, reactive, toRefs } from "vue";
import { Search } from "@vicons/ionicons5";
import { ClearSharp } from "@vicons/material";
import { Filter, Delete, Add } from "@vicons/carbon";

const props = defineProps(["attributes", "filters", "textsearch"]);
const { attributes, filters, textsearch } = toRefs(props);

const emit = defineEmits([
  "addfilter",
  "removefilter",
  "updatefilter",
  "updatetext",
]);

const fields = computed(() => {
  return Object.keys(attributes.value).map((key) => {
    return { name: key, name: key };
  });
});
const attributevalueoption = ref("");
const filterfield = ref(null);
const filtervalue = ref("");
const editeditem = ref(null);
const filteroperator = ref("eq");

const clickedFilterId = ref(null);
const filterMenuStyle = ref({});
const showFilterMenu = ref(false);
const filterRefs = reactive({});
const refnewfilter = ref();

const comptextsearch = ref();

const attributevalueoptionsnaive = computed(() => {
  if (filterfield.value === null) {
    return [];
  }
  let att = attributes.value[filterfield.value];
  console.log(att);
  let list = [];
  att.forEach((item) => {
    list.push({ label: item, value: item });
  });
  return att ? list : [];
});

const attributetype = computed(() => {
  let att = attributes.value[filterfield.value];
  return att ? att.type : [];
});
const attributemulti = computed(() => {
  let att = attributes.value[filterfield.value];
  return att ? att.multi : [];
});
const filterssorted = computed(() => {
  if (!filters.value) {
    return [];
  }
  return filters.value.sort((a, b) => a.id - b.id);
});
const jsonfilters = computed(() => {
  return JSON.stringify(filters);
});
function filtertextclass(f) {
  if (editeditem.value != null && f.id === editeditem.value.id) {
    return "filtertextedit";
  }
  if (f.operator === "eq") {
    return "filtertexteq";
  }
  if (f.operator === "neq") {
    return "filtertextneq";
  }
  return "filtertext";
}

// Method to set the ref dynamically
const setFilterRef = (el, id) => {
  filterRefs[id] = el;
};

const removefilter = (item) => {
  emit("removefilter", item);
  cleanup();
};

const addfilter = () => {
  const item = {
    id: editeditem.value ? editeditem.value.id : 0,
    field: filterfield.value,
    operator: filteroperator.value,
    logic: "or",
    type: attributetype.value,
    values: attributevalueoption.value
      ? attributevalueoption.value
      : filtervalue.value,
  };
  console.log(item);
  if (editeditem.value != null) {
    console.log("update");
    emit("updatefilter", item);
  } else {
    console.log("add");
    emit("addfilter", item);
  }
  cleanup();
};

function editfilter(item) {
  filterfield.value = item.field;
  clickedFilterId.value = item.id;
  filteroperator.value = item.operator;
  if (item.type === "select") {
    attributevalueoption.value = item.values;
  } else {
    filtervalue.value = item.values;
  }
  editeditem.value = item;
  showFilterMenu.value = true;
}

function updatetextsearch() {
  emit("updatetext", comptextsearch.value);
}
function canceledit() {
  cleanup();
}

function cleanup() {
  editeditem.value = null;
  filterfield.value = null;
  showFilterMenu.value = false;
  attributevalueoption.value = null;
}

function addNewFilter() {
  clickedFilterId.value = null;
  showFilterMenu.value = true;
}

watch(textsearch, async (newval) => {
  if (newval) {
    comptextsearch.value = textsearch.value;
  }
});

watch(showFilterMenu, async (newval) => {
  if (newval) {
    positionModal();
  }
});

function positionModal() {
  let button = null;

  if (clickedFilterId.value === null) {
    button = refnewfilter.value;
  } else {
    button = filterRefs[clickedFilterId.value]?.$el;
  }

  const buttonRect = button.getBoundingClientRect();

  filterMenuStyle.value = {
    position: "absolute",
    top: `${buttonRect.bottom}px`,
    left: `${buttonRect.left}px`,
    zIndex: 1000, // or whatever appropriate z-index you need
  };
}

comptextsearch.value = textsearch.value;
</script>

<style>
.filterbox {
  flex-wrap: wrap;
  display: flex;

  gap: 3px;
  padding: 0px;
  background-color: #eeeeee;
  border-radius: 0.3rem;
}

.filteritem {
  display: flex;
  border: 1px solid black;
}
.filternew {
  display: flex;
  padding: 2px;
  /* border: 1px solid black; */
}
.logicbutton {
  margin-left: 2px;
  margin-right: 2px;
}
.filterattribute {
  display: flex;
}
.filtervalue {
  display: flex;
}

.filtertext {
  font-size: x-small;
}

.filtertextedit {
  text-decoration: line-through;
  font-style: oblique;
  background-color: lightcyan;
}
.filtertextneq {
  background-color: lightcoral;
}
.filtertexteq {
  background-color: lightgreen;
}

.filterattribute {
  display: flex;
  width: auto;
  min-width: 100px;
}
.filtertextinput {
  display: flex;
  width: 100px;
  min-width: 100px;
}

.main {
  display: flex;
  border: auto;
  /* margin-top: 100px; */
  justify-content: left;
}

.modalmenu {
  width: auto;
}

.filtermenu {
  width: auto;
  display: flex;
  margin: 0px;
  padding: 0px;
  gap: 2px 2px;
}

.iconbutton {
  margin: 0;
}
</style>
