<script setup lang="ts">
import { Button } from "@/components/ui/button";

defineProps<{
  running: boolean
  canStart: boolean
  busy: boolean
}>();

defineEmits<{
  (event: "start"): void
  (event: "stop"): void
  (event: "history"): void
}>();
</script>

<template>
  <div class="flex items-center gap-2.5">
    <Button :disabled="running || !canStart || busy" @click="$emit('start')">
      开始捕获
    </Button>
    <Button variant="outline" :disabled="!running || busy" @click="$emit('stop')">停止</Button>
    <Button variant="secondary" :disabled="busy" @click="$emit('history')">历史</Button>
  </div>
</template>
