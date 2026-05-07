<script setup lang="ts">
defineProps<{
  modelValue: string
}>();

defineEmits<{
  (event: "update:modelValue", value: string): void
}>();
</script>

<template>
  <label class="search">
    <span>搜索</span>
    <input
      :value="modelValue"
      placeholder="HTTP 头、Host、路径、载荷关键字..."
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
  </label>
</template>

<style scoped>
.search {
  display: grid;
  gap: 6px;
  min-width: 0;
}

span {
  color: var(--muted);
  font-size: 12px;
}

input {
  width: 290px;
  max-width: 100%;
  height: 40px;
  padding: 0 14px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.82);
}
</style>
