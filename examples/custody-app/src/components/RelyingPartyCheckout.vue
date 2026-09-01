<template>
  <q-card class="fh-card q-pa-md full-height column">
    <div class="row items-center q-mb-sm">
      <q-avatar rounded size="34px" style="background:#e0a82e22;color:#e0a82e" class="text-weight-bold">B</q-avatar>
      <div class="q-ml-sm">
        <div class="text-subtitle1 text-weight-medium">BuyStuff <span class="text-caption text-grey-6">· checkout</span></div>
        <div class="text-caption text-grey-6">wants the minimum to complete an order</div>
      </div>
      <q-space />
      <q-chip dense square color="dark" text-color="grey-5" class="fh-mono">tiers 2·3</q-chip>
    </div>

    <q-separator color="grey-9" class="q-mb-md" />

    <div v-if="!granted" class="col column justify-center items-center text-center q-py-md">
      <div class="text-grey-5 q-mb-md">This app never sees your birth date or card number — it asks the vault for a <i>yes/no</i> and a <i>charge</i>.</div>
      <q-btn color="warning" text-color="dark" unelevated icon="shopping_cart" label="Start checkout" @click="start" :loading="busy" />
    </div>

    <div v-else class="col column q-gutter-sm">
      <q-item class="rounded-borders" :class="step.age ? 'bg-green-10' : ''">
        <q-item-section avatar><q-icon :name="step.age ? 'check_circle' : 'cake'" :color="step.age ? 'positive' : 'grey-6'" /></q-item-section>
        <q-item-section>
          <q-item-label>Age check <q-badge outline class="fh-tier-2 q-ml-xs" label="T2 attest" /></q-item-label>
          <q-item-label caption class="text-grey-5">{{ step.age || 'confirm you are 18+ (DOB stays in the vault)' }}</q-item-label>
        </q-item-section>
        <q-item-section side><q-btn dense outline color="info" label="Verify" :disable="!!step.age" @click="verifyAge" /></q-item-section>
      </q-item>

      <q-item class="rounded-borders" :class="step.ship ? 'bg-orange-10' : ''">
        <q-item-section avatar><q-icon :name="step.ship ? 'check_circle' : 'local_shipping'" :color="step.ship ? 'warning' : 'grey-6'" /></q-item-section>
        <q-item-section>
          <q-item-label>Shipping <q-badge outline class="fh-tier-3 q-ml-xs" label="T3 disclose" /></q-item-label>
          <q-item-label caption class="text-grey-5">{{ step.ship || 'disclose the shipping address to the app' }}</q-item-label>
        </q-item-section>
        <q-item-section side><q-btn dense outline color="warning" label="Share" :disable="!step.age || !!step.ship" @click="getShipping" /></q-item-section>
      </q-item>

      <q-item class="rounded-borders" :class="step.pay ? 'bg-orange-10' : ''">
        <q-item-section avatar><q-icon :name="step.pay ? 'check_circle' : 'credit_card'" :color="step.pay ? 'warning' : 'grey-6'" /></q-item-section>
        <q-item-section>
          <q-item-label>Payment <q-badge outline class="fh-tier-3 q-ml-xs" label="T3 borrow" /></q-item-label>
          <q-item-label caption class="text-grey-5">{{ step.pay || 'charge via AcmePay — the app never sees the card' }}</q-item-label>
        </q-item-section>
        <q-item-section side><q-btn dense outline color="warning" label="Pay" :disable="!step.ship || !!step.pay" @click="pay" /></q-item-section>
      </q-item>

      <q-banner v-if="step.pay" dense class="rounded-borders q-mt-sm text-caption" style="background:rgba(35,196,168,.10)">
        <template #avatar><q-icon name="verified" color="positive" /></template>
        Order complete. BuyStuff received: a <b>yes</b>, your <b>shipping address</b>, and a <b>receipt</b> — never your DOB or card number.
      </q-banner>
    </div>
  </q-card>
</template>

<script setup>
import { reactive, ref, computed } from 'vue';
import { useFreehold } from '../freehold/store.js';
const { client } = useFreehold();
const busy = ref(false);
const c = computed(() => client('BuyStuff'));
const granted = ref(false);
const step = reactive({ age: '', ship: '', pay: '' });

async function start() {
  busy.value = true;
  try {
    const ok = await c.value.request(
      ['profile.attest.over18', 'profile.read', 'profile.borrow'],
      'verify age, ship, and charge for your order');
    granted.value = ok;
  } finally { busy.value = false; }
}
async function verifyAge() {
  const r = await c.value.call('profile.attest.over18');
  step.age = r.value ? '✓ verified 18+ — your date of birth never left the vault' : '✗ not eligible';
}
async function getShipping() {
  const r = await c.value.call('profile.read', { fields: ['shipping_addr'] });
  step.ship = `ship to: ${r.shipping_addr}`;
}
async function pay() {
  const r = await c.value.call('profile.borrow', { field: 'card', processor: 'AcmePay' });
  step.pay = `charged via ${r.processor} · ${r.receipt} · retainedByApp=${r.retainedByApp}`;
}
</script>
