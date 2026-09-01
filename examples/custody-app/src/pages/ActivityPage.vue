<template>
  <q-page class="q-pa-lg" style="max-width:900px;margin:0 auto">
    <div class="text-h5 text-weight-bold q-mb-xs">Activity</div>
    <div class="text-grey-6 q-mb-md">The disclosure ledger — who asked for what, and why. It lives in your own sealed vault, so the audit trail is yours too.</div>

    <div class="row q-gutter-sm q-mb-md">
      <q-chip square dense color="dark" text-color="positive" icon="circle">tier 1 · vault-only</q-chip>
      <q-chip square dense color="dark" text-color="info" icon="circle">tier 2 · attestation (fact only)</q-chip>
      <q-chip square dense color="dark" text-color="warning" icon="circle">tier 3 · disclosure / borrow</q-chip>
      <q-space />
      <q-chip square dense color="dark" text-color="grey-4" class="fh-mono">apps hold 0 keys</q-chip>
    </div>

    <q-timeline v-if="state.ledger.length" color="primary">
      <q-timeline-entry v-for="(e, i) in state.ledger" :key="i"
        :color="tierColor(e.tier)" :icon="tierIcon(e.tier)">
        <template #title>
          <span class="text-body2">{{ e.app }}</span>
          <q-chip dense square class="q-ml-sm fh-mono" color="dark" text-color="grey-4">{{ e.cap }}</q-chip>
          <q-badge :class="'fh-tier-' + e.tier" outline class="q-ml-xs" :label="'T' + e.tier" />
        </template>
        <template #subtitle><span class="fh-mono text-grey-6">{{ time(e.ts) }}</span></template>
        <div class="text-grey-4">{{ e.detail }}</div>
      </q-timeline-entry>
    </q-timeline>

    <q-card v-else class="fh-card q-pa-xl text-center text-grey-6">
      <q-icon name="receipt_long" size="40px" class="q-mb-sm" />
      <div>No disclosures yet. Head to <b>Try an app</b> and watch them land here in real time.</div>
    </q-card>
  </q-page>
</template>

<script setup>
import { useFreehold } from '../freehold/store.js';
const { state } = useFreehold();
const tierColor = (t) => ({ 1: 'positive', 2: 'info', 3: 'warning' }[t] || 'primary');
const tierIcon = (t) => ({ 1: 'inventory_2', 2: 'verified', 3: 'north_east' }[t] || 'circle');
const time = (ts) => new Date(ts).toLocaleString();
</script>
