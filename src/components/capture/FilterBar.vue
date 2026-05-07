<script setup lang="ts">
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";

import { formatProtocol } from "../../utils/format";
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
  <div class="flex min-w-0 flex-wrap items-center gap-2">
    <Button
      v-for="protocol in PROTOCOL_OPTIONS"
      :key="protocol"
      variant="outline"
      size="sm"
      class="bg-white/80"
      :class="selectedProtocols.includes(protocol) ? 'border-blue-200 bg-blue-50 text-blue-700' : 'text-slate-500'"
      @click="$emit('toggle-protocol', protocol)"
    >
      {{ formatProtocol(protocol) }}
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
.compact {
  width: 110px;
  background: rgba(255, 255, 255, 0.82);
}

.checkbox {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 0 12px;
  border: 1px solid rgb(226 232 240 / 0.9);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.82);
  color: rgb(100 116 139);
  font-size: 13px;
}
</style>
