<template>
  <router-view v-if="state.status === 'unlocked'" />
  <UnlockPage v-else />
  <ConsentDialog />
</template>

<script setup>
import { onMounted } from 'vue';
import { useFreehold } from './freehold/store.js';
import UnlockPage from './pages/UnlockPage.vue';
import ConsentDialog from './components/ConsentDialog.vue';

const { state, boot } = useFreehold();
onMounted(boot);
</script>

<style>
:root { --fh-glow: 0 0 0 1px rgba(124,107,255,.25), 0 8px 40px rgba(124,107,255,.10); }
body { background: radial-gradient(1200px 600px at 80% -10%, rgba(124,107,255,.10), transparent 60%), #0b0d14; }
.fh-mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
.fh-grad-text { background: linear-gradient(90deg, #a89bff, #7c6bff 60%, #23c4a8); -webkit-background-clip: text; background-clip: text; color: transparent; }
.fh-tier-1 { color: #23c4a8; } .fh-tier-2 { color: #6b9cff; } .fh-tier-3 { color: #e0a82e; }
.fh-card { background: #12151f; border: 1px solid #222738; border-radius: 16px; }
</style>
