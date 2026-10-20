import { createApp } from "vue";
import App from "./App.vue";
import Term from "./components/Term.vue";
import { vTip } from "./lib/tooltip.js";
import "./styles.css";

createApp(App).directive("tip", vTip).component("Term", Term).mount("#app");
