(() => {
  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  const resetToTop = () => {
    const root = document.documentElement;
    const previous = root.style.scrollBehavior;
    root.style.scrollBehavior = 'auto';
    window.scrollTo(0, 0);
    root.style.scrollBehavior = previous;
  };
  resetToTop();
  window.addEventListener('load', resetToTop, { once: true });

  const heroVideo = document.querySelector('.hero-video');
  if (heroVideo) {
    heroVideo.muted = true;
    const playHeroVideo = () => {
      const playback = heroVideo.play();
      if (playback) playback.catch(() => {});
    };
    if (heroVideo.readyState >= 2) playHeroVideo();
    else heroVideo.addEventListener('canplay', playHeroVideo, { once: true });
    heroVideo.addEventListener('pause', () => {
      if (!document.hidden) playHeroVideo();
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) playHeroVideo();
    });
  }

  const loopCanvas = document.querySelector('.loop-canvas');
  if (loopCanvas && loopCanvas.getContext) {
    const loopVisual = loopCanvas.closest('.loop-visual');
    const context = loopCanvas.getContext('2d');
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const TAU = Math.PI * 2;
    let width = 0;
    let height = 0;
    let particles = [];
    let bucketData = [];
    let bucketCounts = new Uint32Array(6);
    let running = false;
    let visible = true;
    let animationId = 0;
    let elapsed = 0;
    let lastFrame = 0;
    let lastDraw = 0;

    const buildParticles = () => {
      const count = Math.max(3600, Math.min(22000, Math.round((width * height) / 12)));
      particles = Array.from({ length: count }, () => {
        const core = Math.random() < 0.2;
        const radius = core ? Math.random() * 0.06 : Math.pow(Math.random(), 1.45) * 0.28;
        const phi = Math.acos(2 * Math.random() - 1);
        const theta = Math.random() * TAU;
        return {
          t: Math.random() * TAU,
          ox: Math.sin(phi) * Math.cos(theta) * radius,
          oy: Math.sin(phi) * Math.sin(theta) * radius,
          oz: Math.cos(phi) * radius,
          speed: core ? 0.00013 : 0.000055 + Math.random() * 0.00006,
          size: core ? 1.1 + Math.random() * 0.7 : 0.6 + Math.random() * 0.95,
          alpha: core ? 0.5 + Math.random() * 0.28 : 0.16 + Math.random() * 0.32,
        };
      });
      bucketData = Array.from({ length: 6 }, () => new Float32Array(count * 3));
      bucketCounts = new Uint32Array(6);
    };

    const draw = (time) => {
      context.clearRect(0, 0, width, height);
      const cx = width / 2;
      const cy = height / 2;
      const yaw = 0.35 + Math.sin(time * 0.00012) * 0.07;
      const tilt = 0.42;
      const cosYaw = Math.cos(yaw);
      const sinYaw = Math.sin(yaw);
      const cosTilt = Math.cos(tilt);
      const sinTilt = Math.sin(tilt);
      const scale = Math.min(width / 2.05, height / 1.65);
      const pulse = 0.93 + Math.sin(time * 0.0012) * 0.07;

      context.beginPath();
      for (let i = 0; i <= 160; i += 1) {
        const t = (i / 160) * TAU;
        const sinT = Math.sin(t);
        const cosT = Math.cos(t);
        const x = sinT;
        const y = 0.55 * (2 * sinT * cosT);
        const z = 0.34 * cosT;
        const yawedX = x * cosYaw - z * sinYaw;
        const yawedZ = x * sinYaw + z * cosYaw;
        const tiltedY = y * cosTilt - yawedZ * sinTilt;
        const px = cx + yawedX * scale;
        const py = cy - tiltedY * scale;
        if (i === 0) context.moveTo(px, py);
        else context.lineTo(px, py);
      }
      context.globalCompositeOperation = 'source-over';
      context.strokeStyle = 'rgba(255, 255, 255, .16)';
      context.lineWidth = 1;
      context.stroke();

      bucketCounts.fill(0);
      for (const particle of particles) {
        const t = particle.t + time * particle.speed;
        const sinT = Math.sin(t);
        const cosT = Math.cos(t);
        const x = sinT + particle.ox;
        const y = 0.55 * (2 * sinT * cosT) + particle.oy;
        const z = 0.34 * cosT + particle.oz;
        const yawedX = x * cosYaw - z * sinYaw;
        const yawedZ = x * sinYaw + z * cosYaw;
        const tiltedY = y * cosTilt - yawedZ * sinTilt;
        const depth = y * sinTilt + yawedZ * cosTilt;
        const px = cx + yawedX * scale;
        const py = cy - tiltedY * scale;
        const depthLight = Math.max(0, Math.min(1, (depth + 0.55) / 1.1));
        const alpha = Math.max(0.05, Math.min(0.95, particle.alpha * (0.42 + depthLight * 0.58) * pulse));
        const size = particle.size * (0.72 + depthLight * 0.55);
        const bucket = Math.min(5, Math.floor(alpha * 6));
        const buffer = bucketData[bucket];
        const offset = bucketCounts[bucket];
        buffer[offset] = px;
        buffer[offset + 1] = py;
        buffer[offset + 2] = size;
        bucketCounts[bucket] = offset + 3;
      }

      context.globalCompositeOperation = 'lighter';
      context.fillStyle = '#ffffff';
      for (let index = 0; index < 6; index += 1) {
        const count = bucketCounts[index];
        if (!count) continue;
        context.globalAlpha = ((index + 1) / 6) * 0.75;
        const buffer = bucketData[index];
        for (let i = 0; i < count; i += 3) {
          const x = buffer[i];
          const y = buffer[i + 1];
          const radius = buffer[i + 2];
          context.fillRect(x - radius, y - radius, radius * 2, radius * 2);
        }
      }
    };

    const frame = (now) => {
      if (!running) return;
      if (!lastFrame) lastFrame = now;
      elapsed += now - lastFrame;
      lastFrame = now;
      if (!lastDraw || now - lastDraw >= 32) {
        lastDraw = now;
        draw(elapsed);
      }
      animationId = window.requestAnimationFrame(frame);
    };

    const stop = () => {
      running = false;
      lastFrame = 0;
      lastDraw = 0;
      window.cancelAnimationFrame(animationId);
    };

    const start = () => {
      if (running) return;
      if (motion.matches) {
        draw(0);
        return;
      }
      running = true;
      lastFrame = 0;
      lastDraw = 0;
      animationId = window.requestAnimationFrame(frame);
    };

    const resize = () => {
      const rect = loopVisual.getBoundingClientRect();
      width = Math.max(1, rect.width);
      height = Math.max(1, rect.height);
      const dpr = Math.min(1.5, window.devicePixelRatio || 1);
      loopCanvas.width = Math.round(width * dpr);
      loopCanvas.height = Math.round(height * dpr);
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      buildParticles();
      draw(elapsed);
    };

    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver(([entry]) => {
        visible = entry.isIntersecting;
        if (visible && !document.hidden) start();
        else stop();
      }, { threshold: 0.1 });
      observer.observe(loopVisual);
    } else {
      start();
    }

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) stop();
      else if (visible) start();
    });

    motion.addEventListener?.('change', () => {
      if (motion.matches) {
        stop();
        draw(0);
      } else if (visible && !document.hidden) {
        start();
      }
    });

    if ('ResizeObserver' in window) new ResizeObserver(resize).observe(loopVisual);
    else window.addEventListener('resize', resize);
    resize();
  }

  const deckViewport = document.querySelector('.deck-viewport');
  if (deckViewport) {
    const deck = document.querySelector('.story-deck');
    const panels = [...deckViewport.querySelectorAll('.deck-panel')];
    const tabs = [...document.querySelectorAll('.deck-tab')];
    const deckPrev = document.querySelector('.deck-prev');
    const deckNext = document.querySelector('.deck-next');
    const deckCounter = document.querySelector('.deck-counter');
    const deckProgress = document.querySelector('.deck-progress span');
    const backToTop = document.querySelector('.back-to-top');
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const deckTotal = panels.length;
    let activeDeck = 0;
    let programmaticDeckUntil = 0;

    const updateDeck = (index, { scroll = false } = {}) => {
      activeDeck = Math.max(0, Math.min(deckTotal - 1, index));
      tabs.forEach((tab, i) => {
        const selected = i === activeDeck;
        tab.classList.toggle('is-active', selected);
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
      });
      panels.forEach((panel, i) => {
        const selected = i === activeDeck;
        panel.classList.toggle('is-active', selected);
        panel.toggleAttribute('inert', !selected);
        panel.setAttribute('aria-hidden', String(!selected));
      });
      if (deckCounter) {
        deckCounter.textContent = `${String(activeDeck + 1).padStart(2, '0')} / ${String(deckTotal).padStart(2, '0')}`;
      }
      if (deckPrev) deckPrev.disabled = activeDeck === 0;
      if (deckNext) deckNext.disabled = activeDeck === deckTotal - 1;
      updateReadingState();
      if (!scroll) return;
      programmaticDeckUntil = Date.now() + 350;
      deckViewport.scrollTo({ left: activeDeck * deckViewport.clientWidth, behavior: 'auto' });
    };

    const revealTarget = (target) => {
      const panel = target.closest('.deck-panel');
      if (!panel) return false;
      const index = panels.indexOf(panel);
      updateDeck(index, { scroll: true });
      const panelTop = panel.getBoundingClientRect().top;
      const targetTop = target.getBoundingClientRect().top;
      const top = target === panel ? 0 : Math.max(0, panel.scrollTop + targetTop - panelTop - 18);
      panel.scrollTo({ top, behavior: 'auto' });
      deck.scrollIntoView({ behavior: 'auto', block: 'start' });
      window.dispatchEvent(new Event('scroll'));
      updateReadingState();
      return true;
    };

    const updateReadingState = () => {
      const panel = panels[activeDeck];
      if (!panel) return;
      const maxScroll = panel.scrollHeight - panel.clientHeight;
      if (deckProgress) {
        const progress = maxScroll > 0 ? Math.min(100, Math.max(0, (panel.scrollTop / maxScroll) * 100)) : 0;
        deckProgress.style.width = `${progress}%`;
      }
      if (backToTop) backToTop.classList.toggle('is-visible', panel.scrollTop > 280);
    };

    panels.forEach((panel) => panel.addEventListener('scroll', updateReadingState, { passive: true }));
    window.addEventListener('resize', updateReadingState);
    backToTop?.addEventListener('click', () => {
      const panel = panels[activeDeck];
      const behavior = reduceMotion.matches ? 'auto' : 'smooth';
      if (panel && panel.scrollTop > 0) panel.scrollTo({ top: 0, behavior });
      else window.scrollTo({ top: 0, behavior });
    });

    deckViewport.addEventListener('scroll', () => {
      if (Date.now() < programmaticDeckUntil) return;
      updateDeck(Math.round(deckViewport.scrollLeft / Math.max(1, deckViewport.clientWidth)));
    }, { passive: true });

    tabs.forEach((tab, i) => {
      tab.addEventListener('click', () => updateDeck(i, { scroll: true }));
      tab.addEventListener('keydown', (event) => {
        if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = activeDeck;
        if (event.key === 'ArrowRight') next = Math.min(deckTotal - 1, activeDeck + 1);
        if (event.key === 'ArrowLeft') next = Math.max(0, activeDeck - 1);
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = deckTotal - 1;
        updateDeck(next, { scroll: true });
        tabs[next].focus();
      });
    });

    deckPrev?.addEventListener('click', () => updateDeck(activeDeck - 1, { scroll: true }));
    deckNext?.addEventListener('click', () => updateDeck(activeDeck + 1, { scroll: true }));
    deckViewport.addEventListener('keydown', (event) => {
      if (event.target !== deckViewport) return;
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault();
      updateDeck(activeDeck + (event.key === 'ArrowRight' ? 1 : -1), { scroll: true });
    });

    document.querySelectorAll('a[href^="#"]').forEach((link) => {
      const target = document.getElementById(link.hash.slice(1));
      if (!target || !target.closest('.deck-panel')) return;
      link.addEventListener('click', (event) => {
        event.preventDefault();
        revealTarget(target);
      });
    });

    updateDeck(0);
  }

  const chapterLinks = [...document.querySelectorAll('.chapter-index a[href^="#"]')];
  const chapterTargets = chapterLinks
    .map((link) => ({ link, section: document.getElementById(link.hash.slice(1)) }))
    .filter(({ section }) => section);
  if (chapterTargets.length) {
    const setCurrent = (id) => {
      for (const link of chapterLinks) {
        if (link.hash === `#${id}`) link.setAttribute('aria-current', 'location');
        else link.removeAttribute('aria-current');
      }
    };
    const updateCurrent = () => {
      const line = window.innerHeight * 0.22;
      let current = chapterTargets[0];
      for (const target of chapterTargets) {
        if (target.section.getBoundingClientRect().top <= line) current = target;
      }
      if (current) setCurrent(current.section.id);
    };
    window.addEventListener('scroll', updateCurrent, { passive: true });
    window.addEventListener('resize', updateCurrent);
    window.addEventListener('hashchange', updateCurrent);
    document.querySelector('.deck-problem')?.addEventListener('scroll', updateCurrent, { passive: true });
    updateCurrent();
  }

  const moduleCarousel = document.querySelector('.module-carousel');
  if (moduleCarousel) {
    const moduleCards = [...moduleCarousel.querySelectorAll('.module-card')];
    const railSteps = [...document.querySelectorAll('.module-rail .rail-step')];
    const modulePrev = document.querySelector('.module-nav-prev');
    const moduleNext = document.querySelector('.module-nav-next');
    const moduleCounter = document.querySelector('.module-counter');
    const moduleProgress = document.querySelector('.module-progress-fill');
    const moduleTotal = moduleCards.length;
    let activeModule = 0;
    let programmaticUntil = 0;

    const updateModule = (index, { scroll = false } = {}) => {
      activeModule = Math.max(0, Math.min(moduleTotal - 1, index));
      moduleCards.forEach((card, i) => card.classList.toggle('is-active', i === activeModule));
      railSteps.forEach((step, i) => {
        step.classList.toggle('is-active', i === activeModule);
        if (i === activeModule) step.setAttribute('aria-current', 'true');
        else step.removeAttribute('aria-current');
      });
      if (moduleCounter) {
        moduleCounter.textContent = `${String(activeModule + 1).padStart(2, '0')} / ${String(moduleTotal).padStart(2, '0')}`;
      }
      if (moduleProgress) {
        moduleProgress.style.width = `${((activeModule + 1) / moduleTotal) * 100}%`;
      }
      if (modulePrev) modulePrev.disabled = activeModule === 0;
      if (moduleNext) moduleNext.disabled = activeModule === moduleTotal - 1;
      if (!scroll) return;
      const card = moduleCards[activeModule];
      const left = card.getBoundingClientRect().left - moduleCarousel.getBoundingClientRect().left + moduleCarousel.scrollLeft;
      programmaticUntil = Date.now() + 350;
      moduleCarousel.scrollTo({ left, behavior: 'auto' });
    };

    const nearestModule = () => {
      const leftEdge = moduleCarousel.getBoundingClientRect().left;
      let bestIndex = 0;
      let bestDistance = Infinity;
      moduleCards.forEach((card, i) => {
        const distance = Math.abs(card.getBoundingClientRect().left - leftEdge);
        if (distance < bestDistance) {
          bestDistance = distance;
          bestIndex = i;
        }
      });
      return bestIndex;
    };

    moduleCarousel.addEventListener('scroll', () => {
      if (Date.now() < programmaticUntil) return;
      updateModule(nearestModule());
    }, { passive: true });

    railSteps.forEach((step, i) => step.addEventListener('click', () => updateModule(i, { scroll: true })));
    modulePrev?.addEventListener('click', () => updateModule(activeModule - 1, { scroll: true }));
    moduleNext?.addEventListener('click', () => updateModule(activeModule + 1, { scroll: true }));
    moduleCarousel.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault();
      updateModule(activeModule + (event.key === 'ArrowRight' ? 1 : -1), { scroll: true });
    });
    updateModule(0);
  }
})();
