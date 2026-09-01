<template>
  <q-page class="q-pa-lg" style="max-width:900px;margin:0 auto">
    <div class="text-h5 text-weight-bold q-mb-xs">Connected apps</div>
    <div class="text-grey-6 q-mb-lg">Every app that asked for access, what it can touch, and a kill switch. Revoke and it loses the door — your data stays with you.</div>

    <template v-if="state.apps.length">
      <q-card v-for="a in state.apps" :key="a.app" class="fh-card q-pa-md q-mb-md">
        <div class="row items-center">
          <q-avatar rounded size="40px" :style="badge(a.app)" class="text-weight-bold">{{ a.app[0] }}</q-avatar>
          <div class="q-ml-md">
            <div class="text-subtitle1 text-weight-medium row items-center">
              {{ a.app }}
              <q-badge v-if="a.active" color="positive" class="q-ml-sm" label="active" />
              <q-badge v-else color="grey-7" class="q-ml-sm" label="revoked" />
            </div>
            <div class="text-caption text-grey-6">purpose: {{ a.purpose || '—' }}</div>
          </div>
          <q-space />
          <q-btn v-if="a.active" outline color="negative" icon="block" label="Revoke" @click="revokeApp(a.app)" />
          <q-chip v-else dense square color="dark" text-color="grey-6" icon="lock">no access</q-chip>
        </div>
        <div v-if="a.scopes.length" class="q-mt-md">
          <div class="text-caption text-grey-6 q-mb-xs">granted capabilities</div>
          <q-chip v-for="s in a.scopes" :key="s" dense square color="dark" text-color="grey-4" class="fh-mono">{{ s }}</q-chip>
        </div>
      </q-card>
    </template>

    <q-card v-else class="fh-card q-pa-xl text-center text-grey-6">
      <q-icon name="apps" size="40px" class="q-mb-sm" />
      <div>No apps have asked for access yet.</div>
      <q-btn flat color="primary" class="q-mt-sm" label="Try an app →" to="/try" />
    </q-card>
  </q-page>
</template>

<script setup>
import { useFreehold } from '../freehold/store.js';
const { state, revokeApp } = useFreehold();
function badge(name) {
  const hues = { Notes: '#23c4a8', 'BuyStuff': '#e0a82e', 'AgeWall': '#6b9cff' };
  const c = hues[name] || '#7c6bff';
  return `background:${c}22;color:${c}`;
}
</script>
