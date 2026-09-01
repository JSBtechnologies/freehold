<template>
  <q-dialog :model-value="!!state.recoveryCode" persistent>
    <q-card class="fh-card" style="min-width:380px;max-width:460px">
      <q-card-section class="row items-center q-pb-none">
        <q-icon name="key" color="warning" size="26px" class="q-mr-sm" />
        <div class="text-h6">Save your recovery code</div>
      </q-card-section>
      <q-card-section>
        <div class="text-grey-5 q-mb-md">A convenience vault's key lives on <b>this device</b>. If you clear
          storage or switch devices, this code is the only way back in. Write it down now — it won't be shown again.</div>
        <div class="fh-mono text-center q-pa-md" style="background:#0d0f16;border:1px solid #2a2f42;border-radius:10px;font-size:16px;letter-spacing:.06em;user-select:all">
          {{ state.recoveryCode }}
        </div>
      </q-card-section>
      <q-card-actions align="between" class="q-pa-md">
        <q-btn flat icon="content_copy" label="Copy" color="grey-4" @click="copy" />
        <q-btn unelevated label="I've saved it" color="warning" text-color="dark" @click="dismissRecoveryCode" />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup>
import { useQuasar } from 'quasar';
import { useFreehold } from '../freehold/store.js';
const { state, dismissRecoveryCode } = useFreehold();
const $q = useQuasar();
function copy() {
  navigator.clipboard?.writeText(state.recoveryCode || '').then(
    () => $q.notify({ message: 'copied', color: 'positive', timeout: 900 }),
    () => {});
}
</script>
