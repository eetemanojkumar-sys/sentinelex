/* Lightweight pointer-based depth effect for SentinelX cards.
   No API calls, dependencies, timers, or telemetry changes. */
(() => {
  "use strict";
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const finePointer = window.matchMedia("(pointer: fine)").matches;
  if (reduceMotion || !finePointer) return;

  const selector = ".metric-card, .panel, .host-card, .server-kpi";
  let active = null;

  function reset(card) {
    if (!card) return;
    card.classList.remove("is-tilting");
    card.style.removeProperty("--tilt-x");
    card.style.removeProperty("--tilt-y");
  }

  document.addEventListener("pointermove", (event) => {
    const card = event.target.closest?.(selector);
    if (card !== active) {
      reset(active);
      active = card;
    }
    if (!card) return;
    const rect = card.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const x = (event.clientX - rect.left) / rect.width;
    const y = (event.clientY - rect.top) / rect.height;
    const rotateY = ((x - 0.5) * 4).toFixed(2);
    const rotateX = ((0.5 - y) * 4).toFixed(2);
    card.style.setProperty("--tilt-x", rotateX + "deg");
    card.style.setProperty("--tilt-y", rotateY + "deg");
    card.classList.add("is-tilting");
  }, { passive: true });

  document.addEventListener("pointerout", (event) => {
    if (!active) return;
    if (event.relatedTarget && active.contains(event.relatedTarget)) return;
    reset(active);
    active = null;
  }, { passive: true });

  window.addEventListener("blur", () => {
    reset(active);
    active = null;
  });
})();
