<template>
  <q-layout view="hHh Lpr lFf">
    <q-header class="bg-transparent">
      <q-toolbar class="q-px-lg" style="height:64px">
        <q-avatar size="30px" class="q-mr-sm">
          <div style="width:22px;height:22px;border-radius:7px;background:linear-gradient(135deg,#7c6bff,#23c4a8)"></div>
        </q-avatar>
        <q-toolbar-title class="text-weight-bold">
          Freehold <span class="text-grey-6 text-caption q-ml-xs">your data, your terms</span>
        </q-toolbar-title>
        <q-chip dense square color="dark" :text-color="state.mode === 'convenience' ? 'warning' : 'positive'"
                :icon="state.mode === 'convenience' ? 'bolt' : 'lock'" class="fh-mono">
          {{ state.mode === 'convenience' ? 'convenience · auto-unlock on this device' : 'passkey · key stays in the vault' }}
        </q-chip>
        <q-btn flat dense round icon="lock" class="q-ml-sm" @click="lock">
          <q-tooltip>Lock (drops the key from memory)</q-tooltip>
        </q-btn>
      </q-toolbar>
    </q-header>

    <q-drawer show-if-above :width="248" :breakpoint="700" class="bg-transparent q-pt-md">
      <q-list padding class="q-px-sm">
        <q-item v-for="n in nav" :key="n.to" clickable :to="n.to" active-class="fh-active"
                class="rounded-borders q-mb-xs">
          <q-item-section avatar><q-icon :name="n.icon" /></q-item-section>
          <q-item-section>
            <q-item-label>{{ n.label }}</q-item-label>
            <q-item-label caption class="text-grey-6">{{ n.hint }}</q-item-label>
          </q-item-section>
        </q-item>
      </q-list>
      <div class="absolute-bottom q-pa-md text-grey-7 text-caption">
        The custody root never leaves this device.<br />Apps are custodians, not owners.
      </div>
    </q-drawer>

    <q-page-container>
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in"><component :is="Component" /></transition>
      </router-view>
    </q-page-container>
  </q-layout>
</template>

<script setup>
import { useFreehold } from '../freehold/store.js';
const { state, lock } = useFreehold();
const nav = [
  { to: '/vault', label: 'Your vault', icon: 'shield', hint: 'the data you own' },
  { to: '/apps', label: 'Connected apps', icon: 'apps', hint: 'grants & revoke' },
  { to: '/activity', label: 'Activity', icon: 'receipt_long', hint: 'disclosure ledger' },
  { to: '/try', label: 'Try an app', icon: 'bolt', hint: 'see custody in action' },
];
</script>

<style scoped>
.fh-active { background: rgba(124,107,255,.14); color: #a89bff; }
.fade-enter-active, .fade-leave-active { transition: opacity .15s ease; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
