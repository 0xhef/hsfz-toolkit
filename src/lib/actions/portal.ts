// Svelte action that teleports a DOM node to a different parent (by
// default, `document.body`) when it mounts, and returns it when the
// action is destroyed. Used to lift modal dialogs and floating toasts
// out of the scrolling `<main>` container inside `MobileShell.svelte`
// so `position: fixed` styling works correctly on Android WebView.
//
// The problem this solves:
//
//   On mobile, panels render inside a flex-column layout where the
//   `<main>` content area has `overflow-y: auto` so the user can
//   scroll panel content without moving the top app bar or bottom
//   nav. A `position: fixed` modal rendered as a descendant of that
//   `<main>` should, per CSS spec, be positioned relative to the
//   viewport. In practice, several Android WebView versions treat
//   overflow-ancestors as containing blocks for fixed positioning
//   and clip the modal to the scroll container, making it either
//   invisible (clipped) or misaligned (scrolling with the content).
//
//   On desktop the layout is normal-flow with body scrolling, so
//   fixed positioning works correctly and the same Svelte code
//   renders the same modal without issues.
//
// The fix is to move the modal's DOM node to document.body at mount
// time so it becomes a sibling of the shell instead of a descendant
// of the scroll container. The Svelte component's reactive bindings
// still work — Svelte tracks the node by reference, not by DOM
// position — so event handlers, $state reactivity, and destroy hooks
// all continue to function exactly as they would in-place.
//
// Usage:
//
//   <script>
//     import { portal } from '../actions/portal';
//   </script>
//
//   {#if status === 'reading'}
//     <div use:portal class="fixed inset-0 z-50 ...">
//       <!-- modal content -->
//     </div>
//   {/if}
//
// The action can optionally take a different target selector:
//
//   <div use:portal={'#modal-root'}>...</div>

export function portal(
  node: HTMLElement,
  target: HTMLElement | string = 'body',
) {
  let targetEl: HTMLElement | null = null;

  function update(newTarget: HTMLElement | string) {
    targetEl =
      typeof newTarget === 'string'
        ? (document.querySelector(newTarget) as HTMLElement | null)
        : newTarget;
    if (!targetEl) {
      console.warn(`[portal] target not found: ${String(newTarget)}`);
      return;
    }
    targetEl.appendChild(node);
  }

  update(target);

  return {
    update,
    destroy() {
      // Svelte's own teardown removes the node from the DOM on {#if}
      // transition; we don't need to do anything here. But if the
      // portal action is destroyed while the node is still mounted
      // (edge case), clean it up just in case.
      if (node.parentNode) {
        node.parentNode.removeChild(node);
      }
    },
  };
}
