import { useMenuStore } from 'spangap-browser/stores/menu'
import AcmePanel from '../panels/AcmePanel.vue'

export function registerAcme() {
  useMenuStore().register('settings', 'Settings', 10, [
    { id: 'network', label: 'Network', type: 'submenu', order: 20,
      children: [
        { id: 'network.acme', label: 'ACME', type: 'panel', order: 50,
          component: AcmePanel },
      ],
    },
  ])
}
