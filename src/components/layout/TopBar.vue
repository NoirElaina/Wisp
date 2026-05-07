<template>
  <header class="topbar">
    <slot />
  </header>
</template>

<style scoped>
.topbar {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(520px, 1fr);
  align-items: end;
  gap: 14px 18px;
  padding: 16px 18px;
  border: 1px solid var(--line);
  border-radius: 20px;
  background: var(--panel-strong);
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
}
</style>
