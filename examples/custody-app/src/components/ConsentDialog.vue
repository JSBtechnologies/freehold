<template>
  <q-dialog :model-value="!!state.consent" persistent>
    <q-card class="fh-card" style="min-width:380px;max-width:440px">
      <q-card-section class="row items-center q-pb-none">
        <q-icon name="fingerprint" color="primary" size="28px" class="q-mr-sm" />
        <div class="text-h6">Consent requested</div>
      </q-card-section>
      <q-card-section v-if="state.consent">
        <div class="q-mb-sm"><b class="text-primary">{{ state.consent.appId }}</b> is asking to access your data.</div>
        <div class="text-caption text-grey-6">it wants:</div>
        <div class="q-mt-xs q-mb-md">
          <q-chip v-for="s in state.consent.scopes" :key="s" dense square color="dark" text-color="grey-3" class="fh-mono">{{ s }}</q-chip>
        </div>
        <div class="text-caption text-grey-6">purpose</div>
        <div class="text-grey-3">{{ state.consent.purpose || '—' }}</div>
        <q-banner dense class="q-mt-md text-caption text-grey-5" style="background:rgba(124,107,255,.08);border-radius:10px">
          Approving records a revocable grant in your vault. The app never receives your key.
        </q-banner>
      </q-card-section>
      <q-card-actions align="right" class="q-pa-md">
        <q-btn flat label="Deny" color="grey-5" @click="respondConsent(false)" />
        <q-btn unelevated label="Approve" color="primary" icon="check" @click="respondConsent(true)" />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup>
import { useFreehold } from '../freehold/store.js';
const { state, respondConsent } = useFreehold();
</script>
