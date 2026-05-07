<script setup lang="ts">
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import type { NetworkInterface } from "../../types/session";

defineProps<{
  interfaces: NetworkInterface[]
  modelValue: string
}>();

defineEmits<{
  (event: "update:modelValue", value: string): void
}>();

function interfaceLabel(item: NetworkInterface): string {
  const primaryAddress = item.addresses.find((address) => address.includes(".")) ?? item.addresses[0] ?? "无 IP";
  const primaryName = prettifyInterfaceName(item);

  return `${primaryName} · ${primaryAddress}`;
}

function prettifyInterfaceName(item: NetworkInterface): string {
  if (item.is_loopback || item.name.includes("Loopback")) {
    return "本地回环";
  }

  const description = item.description.trim();
  if (description && description !== "No interface description") {
    return description;
  }

  if (item.name.startsWith("\\Device\\NPF_")) {
    return "Npcap 网卡";
  }

  return item.name;
}
</script>

<template>
  <div class="select-wrap">
    <span>网卡</span>
    <Select
      :model-value="modelValue"
      @update:model-value="$emit('update:modelValue', typeof $event === 'string' ? $event : '')"
    >
      <SelectTrigger class="trigger">
        <SelectValue placeholder="选择捕获网卡" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem v-for="item in interfaces" :key="item.name" :value="item.name">
          {{ interfaceLabel(item) }}
        </SelectItem>
      </SelectContent>
    </Select>
  </div>
</template>

<style scoped>
.select-wrap {
  display: grid;
  gap: 6px;
  min-width: 0;
}

span {
  color: var(--muted);
  font-size: 12px;
}

.trigger {
  width: min(520px, 100%);
  min-width: 320px;
  height: 40px;
  background: rgba(255, 255, 255, 0.82);
}
</style>
