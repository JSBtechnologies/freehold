<template>
  <q-card class="fh-card q-pa-md full-height column">
    <div class="row items-center q-mb-sm">
      <q-avatar rounded size="34px" style="background:#23c4a822;color:#23c4a8" class="text-weight-bold">N</q-avatar>
      <div class="q-ml-sm">
        <div class="text-subtitle1 text-weight-medium">Notes <span class="text-caption text-grey-6">· custodian</span></div>
        <div class="text-caption text-grey-6">stores its data in your vault — never on a server</div>
      </div>
      <q-space />
      <q-chip dense square color="dark" text-color="positive" class="fh-mono">tier 1</q-chip>
    </div>

    <q-separator color="grey-9" class="q-mb-md" />

    <div v-if="!granted" class="col column justify-center items-center text-center q-py-md">
      <div class="text-grey-5 q-mb-md">A pure custodian: it reads and writes only its <i>own</i> data, and that data lives sealed in your vault. Nothing leaves.</div>
      <q-btn color="positive" text-color="dark" unelevated icon="note_add" label="Connect Notes" @click="connect" :loading="busy" />
    </div>

    <div v-else class="col column">
      <q-input v-model="draft" dense filled dark placeholder="a private note…" @keyup.enter="add" class="q-mb-sm">
        <template #after><q-btn round dense color="positive" text-color="dark" icon="add" @click="add" /></template>
      </q-input>
      <q-scroll-area class="col" style="min-height:120px">
        <q-list>
          <q-item v-for="n in notes" :key="n.id" dense>
            <q-item-section avatar><q-icon name="lock" size="16px" color="grey-7" /></q-item-section>
            <q-item-section>{{ n.body }}</q-item-section>
          </q-item>
          <q-item v-if="!notes.length"><q-item-section class="text-grey-6">no notes yet</q-item-section></q-item>
        </q-list>
      </q-scroll-area>
      <div class="text-caption text-grey-7 q-mt-xs">These bytes are sealed under your DEK. Revoke Notes in “Connected apps” and this data stays yours.</div>
    </div>
  </q-card>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useFreehold } from '../freehold/store.js';
const { client } = useFreehold();
const busy = ref(false);
const c = computed(() => client('Notes'));
const granted = ref(false);
const draft = ref('');
const notes = ref([]);

async function connect() {
  busy.value = true;
  try { granted.value = await c.value.request(['notes.list', 'notes.add', 'notes.clear'], 'keep your private notes'); if (granted.value) await load(); }
  finally { busy.value = false; }
}
async function load() { notes.value = await c.value.call('notes.list'); }
async function add() {
  const body = draft.value.trim(); if (!body) return;
  await c.value.call('notes.add', { body }); draft.value = ''; await load();
}
</script>
