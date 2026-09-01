<template>
  <q-page class="q-pa-lg" style="max-width:900px;margin:0 auto">
    <div class="text-h5 text-weight-bold q-mb-xs">Your vault</div>
    <div class="text-grey-6 q-mb-lg">The data you own outright. Apps only ever see what you grant — and each field can be shared in a different, minimal way.</div>

    <q-card class="fh-card q-pa-md q-mb-md">
      <div class="row items-center q-gutter-sm q-mb-sm">
        <q-icon name="verified_user" color="primary" />
        <div class="text-subtitle1 text-weight-medium">Identity</div>
        <q-space />
        <q-chip dense square color="dark" text-color="grey-5" class="fh-mono">sealed · XChaCha20-Poly1305</q-chip>
      </div>
      <q-list separator>
        <q-item v-for="f in fields" :key="f.k">
          <q-item-section avatar><q-icon :name="f.icon" color="grey-6" /></q-item-section>
          <q-item-section>
            <q-item-label caption class="text-grey-6">{{ f.label }}</q-item-label>
            <q-item-label class="fh-mono">{{ state.profile[f.k] || '—' }}</q-item-label>
          </q-item-section>
          <q-item-section side>
            <div class="row items-center q-gutter-xs">
              <q-badge v-for="b in f.share" :key="b.text" :class="b.cls" outline :label="b.text">
                <q-tooltip>{{ b.tip }}</q-tooltip>
              </q-badge>
              <q-btn flat dense round icon="edit" size="sm" color="grey-6" @click="edit(f)" />
            </div>
          </q-item-section>
        </q-item>
      </q-list>
    </q-card>

    <q-banner class="fh-card text-grey-5">
      <template #avatar><q-icon name="info" color="primary" /></template>
      <b>Date of birth</b> and <b>card</b> are never handed to an app raw — DOB is only usable as an
      <span class="fh-tier-2">18+ attestation</span>, and the card only as a <span class="fh-tier-3">borrow to a processor</span>.
      That's data minimization enforced by the vault, not promised by an app.
    </q-banner>
  </q-page>
</template>

<script setup>
import { useQuasar } from 'quasar';
import { useFreehold } from '../freehold/store.js';
const { state, setField } = useFreehold();
const $q = useQuasar();

const T1 = { text: 'custodian', cls: 'fh-tier-1', tip: 'tier 1 — apps store their own data in your vault' };
const DISC = { text: 'disclosable', cls: 'fh-tier-3', tip: 'tier 3 — can be disclosed raw to an app, logged + revocable' };
const ATT = { text: 'attest only', cls: 'fh-tier-2', tip: 'tier 2 — only a fact (18+) is shared; the value is withheld' };
const BORROW = { text: 'borrow only', cls: 'fh-tier-3', tip: 'tier 3 — released to a processor for one op; the app never sees it' };

const fields = [
  { k: 'name', label: 'Name', icon: 'person', share: [DISC] },
  { k: 'email', label: 'Email', icon: 'mail', share: [DISC, BORROW] },
  { k: 'dob', label: 'Date of birth', icon: 'cake', share: [ATT] },
  { k: 'shipping_addr', label: 'Shipping address', icon: 'local_shipping', share: [DISC, BORROW] },
  { k: 'card', label: 'Payment card', icon: 'credit_card', share: [BORROW] },
];

function edit(f) {
  $q.dialog({ title: `Edit ${f.label}`, prompt: { model: state.profile[f.k] || '', type: 'text' }, cancel: true, dark: true })
    .onOk((v) => setField(f.k, v));
}
</script>
