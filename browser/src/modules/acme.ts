import { useMenuStore } from 'spangap-browser/stores/menu'
import AcmePanel from '../panels/AcmePanel.vue'

export function registerAcme() {
  useMenuStore().register('settings/network/acme', 'ACME', { type: 'panel', component: AcmePanel })
}
