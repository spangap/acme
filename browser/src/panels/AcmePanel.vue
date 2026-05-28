<template>
  <div class="q-gutter-y-md">
    <SettingToggle label="Enable ACME (Let's Encrypt)" k="s.acme.enable" />

    <q-separator dark />

    <div class="q-gutter-y-sm">
      <SettingText label="Domain (FQDN)" k="s.net.dns.fqdn" />
      <SettingSelect
        label="Challenge method"
        k="s.acme.method"
        :options="methodOptions"
      />
      <div class="text-caption text-grey-5" style="line-height: 1.35">
        Empty = auto: DNS-01 if DuckDNS TXT is available, otherwise HTTP-01.
        <span v-if="dnsTxtCapable != null"> DNS TXT API: {{ dnsTxtCapable ? 'yes' : 'no' }}.</span>
      </div>

      <SettingText label="ACME directory URL" k="s.acme.url" />
      <div class="text-caption text-grey-5" style="line-height: 1.35">
        Account URL after first successful run; leave blank on a fresh device until the account is created.
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useDeviceStore } from 'spangap-browser/stores/device'

const device = useDeviceStore()

const methodOptions = [
  { label: 'Auto', value: '' },
  { label: 'DNS-01', value: 'DNS-01' },
  { label: 'HTTP-01', value: 'HTTP-01' },
]

const dnsTxtCapable = computed(() => {
  const v = device.get('dns.txtrecord.capable')
  if (v === undefined || v === null || String(v) === '') return null
  return Number(v) === 1
})
</script>
