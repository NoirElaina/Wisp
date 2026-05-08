<script setup lang="ts">
import type { PacketDetail, FieldNode } from "../../types/packet";

defineProps<{
  packet: PacketDetail
}>();

function fieldKey(prefix: string, field: FieldNode) {
  return `${prefix}:${field.filter_key}:${field.name}`;
}
</script>

<template>
  <div class="grid gap-3">
    <article
      v-for="(layer, layerIndex) in packet.layers"
      :key="`${layer.filter_key}:${layerIndex}`"
      class="rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm"
    >
      <header class="flex items-center justify-between gap-3 border-b border-slate-200/80 px-4 py-3">
        <strong class="text-[13px] text-slate-950">{{ layer.name }}</strong>
        <span class="font-mono text-[11px] text-slate-500">{{ layer.summary }}</span>
      </header>

      <ul class="m-0 grid gap-2 p-4 list-none">
        <li v-for="field in layer.fields" :key="fieldKey(layer.filter_key, field)" class="rounded-xl border border-slate-200/70 bg-slate-50/80 px-3 py-2">
          <div class="flex items-start justify-between gap-3">
            <span class="text-xs text-slate-500">{{ field.name }}</span>
            <span class="value">{{ field.value || "—" }}</span>
          </div>

          <ul v-if="field.children.length > 0" class="mt-2 grid gap-1.5 p-0 list-none">
            <li
              v-for="child in field.children"
              :key="fieldKey(field.filter_key, child)"
              class="flex items-start justify-between gap-3 rounded-lg border border-slate-200/60 bg-white/90 px-2.5 py-2"
            >
              <span class="text-[11px] text-slate-500">{{ child.name }}</span>
              <span class="value">{{ child.value || "—" }}</span>
            </li>
          </ul>
        </li>
      </ul>
    </article>
  </div>
</template>

<style scoped>
.value {
  color: rgb(15 23 42);
  font-size: 12px;
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  text-align: right;
  overflow-wrap: anywhere;
}
</style>
