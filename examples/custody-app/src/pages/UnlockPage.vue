<template>
  <div class="column items-center justify-center window-height q-pa-md">
    <div class="text-center" style="max-width:440px">
      <div style="width:56px;height:56px;border-radius:16px;margin:0 auto 20px;
                  background:linear-gradient(135deg,#7c6bff,#23c4a8);box-shadow:var(--fh-glow)"></div>
      <div class="text-h4 text-weight-bold fh-grad-text q-mb-xs">Freehold</div>
      <div class="text-subtitle1 text-grey-5 q-mb-lg">Your data lives here, sealed by your passkey. Not on a server. Not leased. Yours.</div>

      <q-card class="fh-card q-pa-lg">
        <template v-if="state.status === 'boot'">
          <q-spinner-dots color="primary" size="32px" /><div class="text-grey-6 q-mt-sm">starting the vault…</div>
        </template>

        <template v-else-if="state.status === 'error'">
          <q-icon name="error" color="negative" size="28px" />
          <div class="text-negative q-mt-sm">{{ state.error }}</div>
          <div class="text-caption text-grey-6 q-mt-sm">Needs a secure context + a passkey with the PRF extension.</div>
        </template>

        <template v-else-if="state.status === 'no-vault'">
          <div class="text-body1 q-mb-md">No vault on this device yet. Pick how it unlocks:</div>
          <q-btn color="primary" size="lg" unelevated icon="fingerprint" label="Passkey — no key at rest"
                 :loading="state.busy" @click="enroll" class="full-width q-mb-sm" />
          <div class="text-caption text-grey-6 q-mb-md">Hardened: a biometric unlocks each time; nothing sensitive is ever stored. Best for secrets.</div>
          <q-btn color="warning" text-color="dark" size="lg" unelevated icon="bolt" label="This device — no passkey"
                 :loading="state.busy" @click="enrollConvenience" class="full-width q-mb-sm" outline />
          <div class="text-caption text-grey-6">Convenience: auto-unlocks on this device, no gesture. A device-bound key is kept (non-extractable). For everyday, non-critical data.</div>
        </template>

        <template v-else-if="state.mode === 'convenience'">
          <div class="text-body1 q-mb-md">This vault <b>auto-unlocks on this device</b> — no passkey needed.</div>
          <q-btn color="warning" text-color="dark" size="lg" unelevated icon="bolt" label="Unlock this device"
                 :loading="state.busy" @click="unlock" class="full-width" />
        </template>

        <template v-else>
          <div class="text-body1 q-mb-md">Unlock with your passkey. The key is derived from the gesture and
            <b>zeroized when you lock</b> — this isn't a login, it's the crypto.</div>
          <q-btn color="primary" size="lg" unelevated icon="fingerprint" label="Unlock"
                 :loading="state.busy" @click="unlock" class="full-width" />
        </template>
      </q-card>

      <div class="text-caption text-grey-7 q-mt-md">Every reload re-derives the key from your passkey — nothing sensitive is kept at rest.</div>
    </div>
  </div>
</template>

<script setup>
import { useFreehold } from '../freehold/store.js';
const { state, enroll, enrollConvenience, unlock } = useFreehold();
</script>
