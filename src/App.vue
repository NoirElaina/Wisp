<script setup lang="ts">
import AppShell from "./components/layout/AppShell.vue";
import { Toaster as Sonner } from "@/components/ui/sonner";
</script>

<template>
  <AppShell />
  <Sonner rich-colors position="top-right" />
</template>

<style>
:root {
  color-scheme: light;
  font-family:
    "Segoe UI Variable Display",
    "Segoe UI",
    "SF Pro Display",
    "Helvetica Neue",
    sans-serif;
  font-size: 14px;
  line-height: 1.45;
  font-weight: 450;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  -webkit-text-size-adjust: 100%;

  --bg: #f3f5f7;
  --panel: rgba(255, 255, 255, 0.9);
  --panel-strong: rgba(255, 255, 255, 0.96);
  --line: rgba(12, 18, 28, 0.08);
  --line-strong: rgba(12, 18, 28, 0.14);
  --text: #101828;
  --muted: #667085;
  --subtle: #98a2b3;
  --accent: #155eef;
  --accent-soft: rgba(21, 94, 239, 0.1);
  --success: #027a48;
  --warning: #b54708;
  --danger: #b42318;
  --shadow: 0 18px 48px rgba(15, 23, 42, 0.08);
  background:
    radial-gradient(circle at top left, rgba(21, 94, 239, 0.06), transparent 24%),
    linear-gradient(180deg, #fbfcfd 0%, #eef2f6 100%);
  color: var(--text);
}

* {
  box-sizing: border-box;
}

html,
body,
#app {
  margin: 0;
  min-height: 100vh;
}

body {
  min-width: 1280px;
}

button,
input,
select {
  font: inherit;
}

button {
  cursor: pointer;
}

::selection {
  background: rgba(21, 94, 239, 0.16);
}
</style>
