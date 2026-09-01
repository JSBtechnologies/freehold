<template>
  <q-page class="q-pa-lg" style="max-width:900px;margin:0 auto">
    <div class="text-h5 text-weight-bold q-mb-xs">Try an app</div>
    <div class="text-grey-6 q-mb-lg">These are real relying-party apps. Each holds only a message port to the broker — no key, no database. Watch them ask for the <i>minimum</i>, and see every disclosure land in Activity.</div>

    <div class="row q-col-gutter-md">
      <div class="col-12 col-md-6"><RelyingPartyCheckout /></div>
      <div class="col-12 col-md-6"><RelyingPartyNotes /></div>
    </div>
  </q-page>
</template>

<script setup>
import RelyingPartyCheckout from '../components/RelyingPartyCheckout.vue';
import RelyingPartyNotes from '../components/RelyingPartyNotes.vue';
</script>
