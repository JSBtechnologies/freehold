import { createRouter, createWebHashHistory } from 'vue-router';
import MainLayout from './layouts/MainLayout.vue';
import VaultPage from './pages/VaultPage.vue';
import AppsPage from './pages/AppsPage.vue';
import ActivityPage from './pages/ActivityPage.vue';
import TryPage from './pages/TryPage.vue';

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/', component: MainLayout, children: [
        { path: '', redirect: '/vault' },
        { path: 'vault', name: 'vault', component: VaultPage },
        { path: 'apps', name: 'apps', component: AppsPage },
        { path: 'activity', name: 'activity', component: ActivityPage },
        { path: 'try', name: 'try', component: TryPage },
      ],
    },
  ],
});
