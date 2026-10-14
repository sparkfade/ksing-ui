import { createRouter, createWebHashHistory } from 'vue-router'
import Login from '@/view/Login.vue'
import AdminLayout from '@/layout/AdminLayout.vue'
import UserLayout from '@/layout/UserLayout.vue'
import Dashboard from '@/view/Dashboard.vue'
import Servers from '@/view/Servers.vue'
import Certs from '@/view/Certs.vue'
import Nodes from '@/view/Nodes.vue'
import Users from '@/view/Users.vue'
import Routes from '@/view/Routes.vue'
import Rulesets from '@/view/Rulesets.vue'
import Settings from '@/view/Settings.vue'
import My from '@/view/My.vue'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/login', component: Login },
    {
      path: '/',
      component: AdminLayout,
      children: [
        { path: '', redirect: '/dashboard' },
        { path: 'dashboard', component: Dashboard },
        { path: 'servers', component: Servers },
        { path: 'certs', component: Certs },
        { path: 'nodes', component: Nodes },
        { path: 'users', component: Users },
        { path: 'routes', component: Routes },
        { path: 'rulesets', component: Rulesets },
        { path: 'settings', component: Settings },
      ],
    },
    {
      path: '/my',
      component: UserLayout,
      children: [{ path: '', component: My }],
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  document.title = 'KSING-UI'
  const token = localStorage.getItem('token') || ''
  const role = localStorage.getItem('role') || ''

  if (!token) return to.path === '/login' ? true : '/login'
  if (to.path === '/login') return role === 'admin' ? '/' : '/my'
  if (role === 'admin' && to.path.startsWith('/my')) return '/'
  if (role === 'user' && !to.path.startsWith('/my')) return '/my'
  return true
})

export default router
