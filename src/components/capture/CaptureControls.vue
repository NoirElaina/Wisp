<script setup lang="ts">
defineProps<{
  running: boolean
  canStart: boolean
}>();

defineEmits<{
  (event: "start"): void
  (event: "stop"): void
}>();
</script>

<template>
  <div class="controls">
    <button class="action primary" :disabled="running || !canStart" @click="$emit('start')">
      开始捕获
    </button>
    <button class="action" :disabled="!running" @click="$emit('stop')">停止</button>
  </div>
</template>

<style scoped>
.controls {
  display: flex;
  align-items: center;
  gap: 10px;
}

.action {
  height: 40px;
  padding: 0 16px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.8);
  color: var(--text);
  font-weight: 600;
}

.action:disabled {
  cursor: not-allowed;
  opacity: 0.48;
}

.primary {
  border-color: rgba(21, 94, 239, 0.18);
  background: var(--accent);
  color: white;
}
</style>
