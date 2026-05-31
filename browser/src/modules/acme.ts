import { useMenuStore } from 'spangap-browser/stores/menu'
import AcmePanel from '../panels/AcmePanel.vue'

export function registerAcme() {
  useMenuStore().register('settings', 'Settings', [
    { id: 'network', label: 'Network', type: 'submenu',
      children: [
        { id: 'network.acme', label: 'ACME', type: 'panel',
          component: AcmePanel },
      ],
    },
  ])
}
