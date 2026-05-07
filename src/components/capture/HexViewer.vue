<script setup lang="ts">
defineProps<{
  bytesHex: string
  asciiPreview: string
}>();
</script>

<template>
  <div class="viewer">
    <section>
      <header>十六进制</header>
      <pre>{{ bytesHex }}</pre>
    </section>
    <section>
      <header>ASCII 预览</header>
      <pre>{{ asciiPreview }}</pre>
    </section>
  </div>
</template>

<style scoped>
.viewer {
  display: grid;
  gap: 12px;
}

section {
  border: 1px solid var(--line);
  border-radius: 14px;
  background: #fcfdff;
  overflow: hidden;
}

header {
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

pre {
  margin: 0;
  padding: 12px;
  overflow: auto;
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
}
</style>
