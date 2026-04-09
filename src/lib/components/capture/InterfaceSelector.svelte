<script lang="ts">
  import type { NetworkInterface } from '../../types';

  interface Props {
    interfaces: NetworkInterface[];
    selected: string;
    disabled: boolean;
  }

  let { interfaces, selected = $bindable(), disabled }: Props = $props();
</script>

<div class="mb-4">
  <label
    for="interface-select"
    class="block text-sm font-medium text-[var(--text-secondary)] mb-2"
  >
    Network Interface
  </label>
  <select
    id="interface-select"
    bind:value={selected}
    {disabled}
    class="w-full px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)]
           text-[var(--text-primary)] text-sm
           focus:border-[var(--accent)] focus:outline-none
           disabled:opacity-50 disabled:cursor-not-allowed"
  >
    {#each interfaces as iface}
      <option value={iface.name}>
        {iface.description || iface.name}
        {#if iface.is_loopback}
          (loopback)
        {/if}
      </option>
    {/each}
  </select>
</div>
