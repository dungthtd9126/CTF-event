document.addEventListener("DOMContentLoaded", () => {
  const panels = document.querySelectorAll(".panel, .kpi-card, .hero");
  panels.forEach((el, idx) => {
    el.style.opacity = "0";
    el.style.transform = "translateY(8px)";
    setTimeout(() => {
      el.style.transition = "opacity 280ms ease, transform 280ms ease";
      el.style.opacity = "1";
      el.style.transform = "translateY(0)";
    }, 30 * idx);
  });
});
