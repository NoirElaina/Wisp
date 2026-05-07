<script setup lang="ts">
import { PROTOCOL_OPTIONS } from "../../utils/protocol";

defineProps<{
  selectedProtocols: string[]
  ip: string
  port: string
  onlyMalformed: boolean
}>();

defineEmits<{
  (event: "toggle-protocol", protocol: string): void
  (event: "update:ip", value: string): void
  (event: "update:port", value: string): void
  (event: "update:only-malformed", value: boolean): void
}>();
</script>

<template>
  <div class="filter-bar">
    <button
      v-for="protocol in PROTOCOL_OPTIONS"
      :key="protocol"
      class="pill"
      :class="{ active: selectedProtocols.includes(protocol) }"
      @click="$emit('toggle-protocol', protocol)"
    >
      {{ protocol.toUpperCase() }}
    </button>

    <input
      class="compact"
      :value="ip"
      placeholder="IP 过滤"
      @input="$emit('update:ip', ($event.target as HTMLInputElement).value)"
    />

    <input
      class="compact"
      :value="port"
      placeholder="端口"
      @input="$emit('update:port', ($event.target as HTMLInputElement).value)"
    />

    <label class="checkbox">
      <input
        type="checkbox"
        :checked="onlyMalformed"
        @change="$emit('update:only-malformed', ($event.target as HTMLInputElement).checked)"
      />
      异常包
    </label>
  </div>
</template>

<style scoped>
.filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  min-width: 0;
}

.pill,
.compact,
.checkbox {
  height: 36px;
  border: 1px solid var(--line);
  border-radius: 11px;
  background: rgba(255, 255, 255, 0.78);
}

.pill {
  flex: 0 0 auto;
  padding: 0 12px;
  color: var(--muted);
}

.pill.active {
  border-color: rgba(21, 94, 239, 0.2);
  background: var(--accent-soft);
  color: var(--accent);
}

.compact {
  width: 110px;
  padding: 0 12px;
}

.checkbox {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 0 12px;
  color: var(--muted);
}

.checkbox input {
  margin: 0;
}
</style>
