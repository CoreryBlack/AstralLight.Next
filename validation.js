(() => {
  const progress = document.querySelector('.validation-progress span');
  const backToTop = document.querySelector('.back-to-top');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const update = () => {
    const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
    if (progress) {
      const value = maxScroll > 0 ? Math.min(100, Math.max(0, (window.scrollY / maxScroll) * 100)) : 0;
      progress.style.width = `${value}%`;
    }
    if (backToTop) backToTop.classList.toggle('is-visible', window.scrollY > 620);
  };

  window.addEventListener('scroll', update, { passive: true });
  window.addEventListener('resize', update);
  backToTop?.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: reduceMotion.matches ? 'auto' : 'smooth' });
  });
  update();

  if (!reduceMotion.matches && 'IntersectionObserver' in window) {
    const sections = [...document.querySelectorAll('.validation-section')];
    sections.forEach((section) => section.classList.add('reveal'));
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -6% 0px' });
    sections.forEach((section) => observer.observe(section));
    window.setTimeout(() => {
      sections.forEach((section) => section.classList.add('is-visible'));
    }, 1800);
  }

  const inventoryToggle = document.querySelector('#inventory-toggle');
  const inventoryGroups = [...document.querySelectorAll('.inventory-group')];
  inventoryToggle?.addEventListener('click', () => {
    const expand = inventoryGroups.some((group) => !group.open);
    inventoryGroups.forEach((group) => { group.open = expand; });
    inventoryToggle.textContent = expand ? '收起全部' : '展开全部';
  });
})();
