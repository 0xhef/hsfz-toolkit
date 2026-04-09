<script lang="ts">
  import { open } from '@tauri-apps/plugin-dialog';

  interface Props {
    onFileSelected: (path: string) => void;
  }

  let { onFileSelected }: Props = $props();
  let isDragging = $state(false);

  async function handleBrowse() {
    const path = await open({
      multiple: false,
      filters: [{ name: 'PCAP Files', extensions: ['pcap', 'pcapng', 'cap'] }],
    });

    if (path) {
      onFileSelected(path as string);
    }
  }

  function handleDragOver(e: DragEvent) {
    e.preventDefault();
    isDragging = true;
  }

  function handleDragLeave() {
    isDragging = false;
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    isDragging = false;

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      // Tauri drag-drop provides the file path
      const file = files[0];
      if (file.name.match(/\.(pcap|pcapng|cap)$/i)) {
        // In Tauri, we need the full path. File browser is more reliable.
        handleBrowse();
      }
    }
  }
</script>

<div
  role="button"
  tabindex="0"
  class="p-12 rounded-lg border-2 border-dashed text-center cursor-pointer transition-colors
    {isDragging
      ? 'border-[var(--accent)] bg-[var(--accent)]/10'
      : 'border-[var(--border)] bg-[var(--bg-secondary)] hover:border-[var(--accent)] hover:bg-[var(--bg-tertiary)]'}"
  ondragover={handleDragOver}
  ondragleave={handleDragLeave}
  ondrop={handleDrop}
  onclick={handleBrowse}
  onkeydown={(e) => e.key === 'Enter' && handleBrowse()}
>
  <div class="text-4xl mb-4 opacity-50">&#128194;</div>
  <p class="text-[var(--text-primary)] font-medium">Drop a .pcap file here</p>
  <p class="text-sm text-[var(--text-secondary)] mt-2">or click to browse</p>
  <p class="text-xs text-[var(--text-secondary)] mt-4 opacity-60">
    Supports PCAP files from PCAPdroid, Wireshark, tcpdump
  </p>
</div>
