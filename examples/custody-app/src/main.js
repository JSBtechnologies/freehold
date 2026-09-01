import { createApp } from 'vue';
import { Quasar, Notify, Dialog } from 'quasar';
import '@quasar/extras/material-icons/material-icons.css';
import '@quasar/extras/roboto-font/roboto-font.css';
import 'quasar/src/css/index.sass';
import App from './App.vue';
import router from './router.js';

createApp(App)
  .use(Quasar, { plugins: { Notify, Dialog }, config: { dark: true } })
  .use(router)
  .mount('#app');
