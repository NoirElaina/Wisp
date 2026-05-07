<script setup lang="ts">
import { Input } from "@/components/ui/input";

defineProps<{
  modelValue: string
}>();

defineEmits<{
  (event: "update:modelValue", value: string): void
}>();
</script>

<template>
  <label class="grid min-w-0 gap-1.5">
    <span class="text-xs text-slate-500">搜索</span>
    <Input
      :model-value="modelValue"
      class="search-input"
      placeholder="HTTP 头、Host、路径、载荷关键字..."
      @update:model-value="$emit('update:modelValue', String($event))"
    />
  </label>
</template>

<style scoped>
.search-input {
  width: 290px;
  max-width: 100%;
  height: 40px;
  background: rgba(255, 255, 255, 0.82);
}
</style>
