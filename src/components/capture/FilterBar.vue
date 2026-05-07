<script setup lang="ts">
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";

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
    <Button
      v-for="protocol in PROTOCOL_OPTIONS"
      :key="protocol"
      variant="outline"
      size="sm"
      class="pill"
      :class="selectedProtocols.includes(protocol) ? 'pill-active' : 'pill-idle'"
      @click="$emit('toggle-protocol', protocol)"
    >
      {{ protocol.toUpperCase() }}
    </Button>

    <Input
      class="compact"
      :model-value="ip"
      placeholder="IP 过滤"
      @update:model-value="$emit('update:ip', String($event))"
    />

    <Input
      class="compact"
      :model-value="port"
      placeholder="端口"
      @update:model-value="$emit('update:port', String($event))"
    />

    <label class="checkbox">
      <Checkbox
        :checked="onlyMalformed"
        @update:checked="$emit('update:only-malformed', $event === true)"
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

.pill {
  flex: 0 0 auto;
  background: rgba(255, 255, 255, 0.78);
}

.pill-idle {
  color: var(--muted);
}

.pill-active {
  background: var(--accent-soft);
  color: var(--accent);
  border-color: rgba(21, 94, 239, 0.2);
}

.compact {
  width: 110px;
  background: rgba(255, 255, 255, 0.78);
}

.checkbox {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 0 12px;
  border: 1px solid var(--line);
  border-radius: 11px;
  background: rgba(255, 255, 255, 0.78);
  color: var(--muted);
}
</style>
