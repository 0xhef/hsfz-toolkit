<script lang="ts">
  // Reusable spinner. Used by every panel that needs a "working…"
  // indicator next to a button or in a loading card. Sized via the
  // `size` prop (default 16px) so it scales for both inline button
  // use and prominent loading cards.
  interface Props {
    size?: number;
    /** Border thickness in px. Defaults to size/8 for a balanced look. */
    thickness?: number;
    /** Optional aria-label for screen readers (defaults to "Loading"). */
    label?: string;
  }
  let { size = 16, thickness, label = 'Loading' }: Props = $props();
  const stroke = $derived(thickness ?? Math.max(2, Math.round(size / 8)));
</script>

<span
  role="status"
  aria-label={label}
  style="
    display: inline-block;
    width: {size}px;
    height: {size}px;
    border: {stroke}px solid var(--accent);
    border-top-color: transparent;
    border-radius: 9999px;
    animation: spin 0.9s linear infinite;
    flex-shrink: 0;
  "
></span>

<style>
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
