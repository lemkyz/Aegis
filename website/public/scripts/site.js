(() => {
  'use strict';

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Mobile navigation
  const navToggle = document.querySelector('[data-nav-toggle]');
  const mobilePanel = document.querySelector('[data-mobile-panel]');
  if (navToggle instanceof HTMLButtonElement && mobilePanel instanceof HTMLElement) {
    const close = () => {
      navToggle.setAttribute('aria-expanded', 'false');
      mobilePanel.hidden = true;
      document.documentElement.classList.remove('nav-open');
    };
    navToggle.addEventListener('click', () => {
      const open = navToggle.getAttribute('aria-expanded') !== 'true';
      navToggle.setAttribute('aria-expanded', String(open));
      mobilePanel.hidden = !open;
      document.documentElement.classList.toggle('nav-open', open);
    });
    mobilePanel.querySelectorAll('a').forEach((link) => link.addEventListener('click', close));
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && !mobilePanel.hidden) {
        close();
        navToggle.focus();
      }
    });
  }

  document.querySelectorAll('[data-result-ui]').forEach((root) => {
    const tabs = Array.from(root.querySelectorAll('[data-result-tab]'));
    const panels = Array.from(root.querySelectorAll('[data-result-panel]'));
    const activate = (key, focus = false) => {
      tabs.forEach((tab) => {
        const selected = tab.getAttribute('data-result-tab') === key;
        tab.setAttribute('aria-selected', String(selected));
        tab.setAttribute('tabindex', selected ? '0' : '-1');
        if (selected && focus && tab instanceof HTMLElement) tab.focus();
      });
      panels.forEach((panel) => {
        if (panel instanceof HTMLElement) panel.hidden = panel.getAttribute('data-result-panel') !== key;
      });
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => activate(tab.getAttribute('data-result-tab')));
      tab.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = tabs.length - 1;
        activate(tabs[next].getAttribute('data-result-tab'), true);
      });
    });
  });

  // Hero verification sequence: auto-runs once, never loops.
  document.querySelectorAll('[data-proof-sequence]').forEach((root) => {
    const steps = Array.from(root.querySelectorAll('[data-proof-step]'));
    const button = root.querySelector('[data-run-proof]');
    const state = root.querySelector('[data-proof-state]');
    const progress = root.querySelector('[data-proof-progress]');
    let timerIds = [];

    const clear = () => {
      timerIds.forEach((id) => window.clearTimeout(id));
      timerIds = [];
    };
    const setProgress = (value) => {
      if (progress instanceof HTMLProgressElement) {
        progress.value = value;
        progress.textContent = `${value}%`;
      }
    };
    const finish = () => {
      steps.forEach((step) => {
        step.classList.remove('is-active');
        step.classList.add('is-done');
      });
      setProgress(100);
      if (state) state.textContent = 'REVIEW · active claim preserved';
      if (button instanceof HTMLButtonElement) {
        button.disabled = false;
        button.textContent = 'Run again';
      }
    };
    const run = () => {
      clear();
      steps.forEach((step) => step.classList.remove('is-active', 'is-done'));
      if (button instanceof HTMLButtonElement) {
        button.disabled = true;
        button.textContent = 'Verifying…';
      }
      if (state) state.textContent = 'Evidence chain in progress';
      setProgress(3);
      if (prefersReducedMotion) {
        finish();
        return;
      }
      steps.forEach((step, index) => {
        const start = 220 + index * 390;
        timerIds.push(window.setTimeout(() => {
          step.classList.add('is-active');
          setProgress(Math.round(((index + 0.45) / steps.length) * 100));
        }, start));
        timerIds.push(window.setTimeout(() => {
          step.classList.remove('is-active');
          step.classList.add('is-done');
          setProgress(Math.round(((index + 1) / steps.length) * 100));
          if (index === steps.length - 1) finish();
        }, start + 300));
      });
    };

    if (button instanceof HTMLButtonElement) button.addEventListener('click', run);
    if (!prefersReducedMotion) timerIds.push(window.setTimeout(run, 850));
    else finish();
  });

  // Evidence graph
  document.querySelectorAll('[data-graph]').forEach((root) => {
    const nodes = Array.from(root.querySelectorAll('[data-graph-node]'));
    const title = root.querySelector('[data-graph-title]');
    const detail = root.querySelector('[data-graph-detail]');
    const choose = (node, focus = false) => {
      nodes.forEach((item) => {
        const selected = item === node;
        item.classList.toggle('active', selected);
        item.setAttribute('aria-pressed', String(selected));
      });
      if (title) title.textContent = node.getAttribute('data-title') || '';
      if (detail) detail.textContent = node.getAttribute('data-detail') || '';
      if (focus && node instanceof HTMLElement) node.focus();
    };
    nodes.forEach((node, index) => {
      node.addEventListener('click', () => choose(node));
      node.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowLeft') next = (index - 1 + nodes.length) % nodes.length;
        if (event.key === 'ArrowRight') next = (index + 1) % nodes.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = nodes.length - 1;
        choose(nodes[next], true);
      });
    });
  });

  // Fix & Prove stages
  document.querySelectorAll('[data-fix-lab]').forEach((root) => {
    const buttons = Array.from(root.querySelectorAll('[data-fix-view]'));
    const panes = Array.from(root.querySelectorAll('[data-fix-pane]'));
    const activate = (key, focus = false) => {
      buttons.forEach((button) => {
        const selected = button.getAttribute('data-fix-view') === key;
        button.setAttribute('aria-selected', String(selected));
        button.setAttribute('tabindex', selected ? '0' : '-1');
        if (selected && focus && button instanceof HTMLElement) button.focus();
      });
      panes.forEach((pane) => {
        if (pane instanceof HTMLElement) pane.hidden = pane.getAttribute('data-fix-pane') !== key;
      });
    };
    buttons.forEach((button, index) => {
      button.addEventListener('click', () => activate(button.getAttribute('data-fix-view')));
      button.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + buttons.length) % buttons.length;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % buttons.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = buttons.length - 1;
        activate(buttons[next].getAttribute('data-fix-view'), true);
      });
    });
  });

  // Product-surface tabs
  document.querySelectorAll('[data-surface-tabs]').forEach((root) => {
    const buttons = Array.from(root.querySelectorAll('[data-surface-tab]'));
    const panes = Array.from(root.querySelectorAll('[data-surface-pane]'));
    const select = (key, focus = false) => {
      buttons.forEach((button) => {
        const selected = button.getAttribute('data-surface-tab') === key;
        button.setAttribute('aria-selected', String(selected));
        button.setAttribute('tabindex', selected ? '0' : '-1');
        if (selected && focus && button instanceof HTMLElement) button.focus();
      });
      panes.forEach((pane) => {
        if (pane instanceof HTMLElement) pane.hidden = pane.getAttribute('data-surface-pane') !== key;
      });
    };
    buttons.forEach((button, index) => {
      button.addEventListener('click', () => select(button.getAttribute('data-surface-tab')));
      button.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowLeft') next = (index - 1 + buttons.length) % buttons.length;
        if (event.key === 'ArrowRight') next = (index + 1) % buttons.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = buttons.length - 1;
        select(buttons[next].getAttribute('data-surface-tab'), true);
      });
    });
  });

  // V7 product surface explorer
  document.querySelectorAll('[data-surface-explorer]').forEach((root) => {
    const choices = Array.from(root.querySelectorAll('[data-surface-choice]'));
    const scenes = Array.from(root.querySelectorAll('[data-surface-scene]'));
    const activate = (key, focus = false) => {
      choices.forEach((choice) => {
        const selected = choice.getAttribute('data-surface-choice') === key;
        choice.classList.toggle('active', selected);
        choice.setAttribute('aria-selected', String(selected));
        choice.setAttribute('tabindex', selected ? '0' : '-1');
        if (selected && focus && choice instanceof HTMLElement) choice.focus();
      });
      scenes.forEach((scene) => {
        const active = scene.getAttribute('data-surface-scene') === key;
        scene.classList.toggle('active', active);
        if (scene instanceof HTMLElement) scene.hidden = !active;
      });
    };
    choices.forEach((choice, index) => {
      choice.addEventListener('click', () => activate(choice.getAttribute('data-surface-choice')));
      choice.addEventListener('keydown', (event) => {
        if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + choices.length) % choices.length;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % choices.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = choices.length - 1;
        activate(choices[next].getAttribute('data-surface-choice'), true);
      });
    });
    root.querySelectorAll('[data-surface-note]').forEach((button) => {
      button.addEventListener('click', () => {
        const scene = button.closest('[data-surface-scene]');
        const output = scene?.querySelector('[data-surface-note-output]');
        scene?.querySelectorAll('[data-surface-note]').forEach((item) => item.classList.toggle('active', item === button));
        if (output) output.textContent = button.getAttribute('data-surface-note') || '';
      });
    });
  });

  // Real repository capture: fit or inspect at 100% inside a scrollable viewport.
  document.querySelectorAll('[data-repo-real]').forEach((root) => {
    const controls = Array.from(root.querySelectorAll('[data-repo-zoom]'));
    const viewport = root.querySelector('[data-repo-viewport]');
    controls.forEach((button) => button.addEventListener('click', () => {
      const mode = button.getAttribute('data-repo-zoom');
      root.classList.toggle('is-full', mode === 'full');
      controls.forEach((item) => {
        const selected = item === button;
        item.classList.toggle('active', selected);
        item.setAttribute('aria-pressed', String(selected));
      });
      if (viewport instanceof HTMLElement) viewport.scrollTo({left:0, top:0, behavior: prefersReducedMotion ? 'auto' : 'smooth'});
    }));
  });

  // Restrained reveal motion. Content remains visible if JS is disabled.
  if (!prefersReducedMotion && 'IntersectionObserver' in window) {
    const revealTargets = document.querySelectorAll('.section-head, .research-grid > a, .pricing-plan-link, .surface-explorer, .repo-real, .contact-home-panel');
    revealTargets.forEach((item) => item.classList.add('reveal-ready'));
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('reveal-in');
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });
    revealTargets.forEach((item) => observer.observe(item));
  }

  // Copy buttons
  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!(button instanceof HTMLButtonElement)) return;
      const value = button.getAttribute('data-copy') || '';
      const original = button.textContent || 'Copy';
      try {
        await navigator.clipboard.writeText(value);
        button.textContent = 'Copied';
      } catch {
        button.textContent = 'Copy manually';
      }
      window.setTimeout(() => { button.textContent = original; }, 1400);
    });
  });

  // Static contact form: no backend, no network request. Opens user's mail client.
  document.querySelectorAll('[data-contact-form]').forEach((form) => {
    if (!(form instanceof HTMLFormElement)) return;
    const targetEmail = form.getAttribute('data-contact-email') || '';
    const status = form.querySelector('[data-contact-status]');
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      if (!form.reportValidity() || !targetEmail) return;
      const data = new FormData(form);
      const interest = String(data.get('interest') || 'general');
      const routeEmail = interest === 'investor' ? 'founder@aegistrustlayer.com' : (['design-partner','team','enterprise','research','partner'].includes(interest) ? 'partnerships@aegistrustlayer.com' : targetEmail);
      const subject = `Aegis enquiry — ${String(data.get('company') || data.get('name') || 'website')}`;
      const body = [
        `Name: ${String(data.get('name') || '')}`,
        `Email: ${String(data.get('email') || '')}`,
        `Company: ${String(data.get('company') || '')}`,
        `Team size: ${String(data.get('team') || '')}`,
        `Interest: ${String(data.get('interest') || '')}`,
        '',
        String(data.get('message') || ''),
      ].join('\n');
      if (status) status.textContent = 'Opening your email client. This website does not submit or store the form.';
      window.location.href = `mailto:${routeEmail}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    });
  });

  // Build-time GitHub repository snapshot viewer
  document.querySelectorAll('[data-repo-window]').forEach((root) => {
    const buttons = Array.from(root.querySelectorAll('[data-repo-tab]'));
    const panels = Array.from(root.querySelectorAll('[data-repo-panel]'));
    const select = (key) => {
      buttons.forEach((button) => button.classList.toggle('active', button.getAttribute('data-repo-tab') === key));
      panels.forEach((panel) => {
        const active = panel.getAttribute('data-repo-panel') === key;
        panel.classList.toggle('active', active);
        if (panel instanceof HTMLElement) panel.hidden = !active;
      });
    };
    buttons.forEach((button) => button.addEventListener('click', () => select(button.getAttribute('data-repo-tab'))));
  });

  document.querySelectorAll('[data-copy-code]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!(button instanceof HTMLButtonElement)) return;
      const code = button.closest('.repo-code')?.querySelector('code')?.textContent || '';
      const original = button.textContent || 'Copy';
      try {
        await navigator.clipboard.writeText(code);
        button.textContent = 'Copied';
      } catch {
        button.textContent = 'Select text';
      }
      window.setTimeout(() => { button.textContent = original; }, 1400);
    });
  });


  // V8 build-time repository browser.
  document.querySelectorAll('[data-repo-browser]').forEach((root) => {
    const buttons = Array.from(root.querySelectorAll('[data-repo-tab]'));
    const panels = Array.from(root.querySelectorAll('[data-repo-panel]'));
    const select = (key, focus = false) => {
      buttons.forEach((button) => {
        const selected = button.getAttribute('data-repo-tab') === key;
        button.setAttribute('aria-selected', String(selected));
        if (selected && focus && button instanceof HTMLElement) button.focus();
      });
      panels.forEach((panel) => {
        if (panel instanceof HTMLElement) panel.hidden = panel.getAttribute('data-repo-panel') !== key;
      });
    };
    buttons.forEach((button, index) => {
      button.addEventListener('click', () => select(button.getAttribute('data-repo-tab')));
      button.addEventListener('keydown', (event) => {
        if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowLeft') next = (index - 1 + buttons.length) % buttons.length;
        if (event.key === 'ArrowRight') next = (index + 1) % buttons.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = buttons.length - 1;
        select(buttons[next].getAttribute('data-repo-tab'), true);
      });
    });
  });

  // Security boundary explorer: copy changes, the trust model does not.
  const boundaryCopy = {
    local: {
      status: 'LOCAL', cap: 'DEFAULT DESTINATION', target: 'Local evidence + policy', state: 'No network required',
      eyebrow: 'Deterministic workflow', title: 'Security analysis can stay on the developer machine.',
      body: 'Deterministic scans, policy evaluation, audit records, and project security memory remain local in the current VS Code workflow. A model provider is not required for the deterministic path.',
      facts: ['no product telemetry in 0.2.0', 'local loopback backend', 'evidence stays inspectable']
    },
    models: {
      status: 'EXPLICIT', cap: 'WHEN MODEL REVIEW IS ENABLED', target: 'Configured provider', state: 'Route recorded in evidence',
      eyebrow: 'Model-provider boundary', title: 'Model-backed review is optional—and visible when used.',
      body: 'When model-backed review is enabled, Aegis sends the configured provider only the source context and evidence required for that request after its secret-redaction boundary. The report records the provider and model used for each role.',
      facts: ['provider route is explicit', 'primary and verifier remain separate', 'deterministic path still exists']
    },
    validation: {
      status: 'AUTHORIZED', cap: 'CONTROLLED EXECUTION', target: 'Local container boundary', state: 'Network off by default',
      eyebrow: 'Dynamic validation', title: 'Analysis permission is not execution permission.',
      body: 'Controlled validation is never implicit. It requires separate authorization and uses a constrained local container boundary with a read-only repository mount, dropped Linux capabilities, no-new-privileges, an unprivileged user, and resource limits.',
      facts: ['read-only repository mount', 'network disabled by default', 'bounded CPU · memory · runtime']
    },
    website: {
      status: 'STATIC', cap: 'PUBLIC WEB SURFACE', target: 'Static HTML + assets', state: 'No app backend',
      eyebrow: 'Website attack surface', title: 'The public site deliberately does less.',
      body: 'The Aegis public website has no login, session, database, remote JavaScript, third-party analytics, or contact-form API. Its production headers deny framing and object embedding, restrict script and network sources, and upgrade requests to HTTPS.',
      facts: ['no account/session surface', 'no third-party analytics', 'strict security headers']
    }
  };
  document.querySelectorAll('[data-boundary-explorer]').forEach((root) => {
    const buttons = Array.from(root.querySelectorAll('[data-boundary]'));
    const status = root.querySelector('[data-boundary-status]');
    const targetCap = root.querySelector('[data-boundary-target-cap]');
    const target = root.querySelector('[data-boundary-target]');
    const targetState = root.querySelector('[data-boundary-target-state]');
    const eyebrow = root.querySelector('[data-boundary-eyebrow]');
    const title = root.querySelector('[data-boundary-title]');
    const body = root.querySelector('[data-boundary-body]');
    const facts = root.querySelector('[data-boundary-facts]');
    const activate = (key, focus = false) => {
      const data = boundaryCopy[key];
      if (!data) return;
      buttons.forEach((button) => {
        const selected = button.getAttribute('data-boundary') === key;
        button.classList.toggle('active', selected);
        button.setAttribute('aria-selected', String(selected));
        if (selected && focus && button instanceof HTMLElement) button.focus();
      });
      if (status) status.textContent = data.status;
      if (targetCap) targetCap.textContent = data.cap;
      if (target) target.textContent = data.target;
      if (targetState) targetState.textContent = data.state;
      if (eyebrow) eyebrow.textContent = data.eyebrow;
      if (title) title.textContent = data.title;
      if (body) body.textContent = data.body;
      if (facts) { while (facts.firstChild) facts.removeChild(facts.firstChild); data.facts.forEach((item) => { const span = document.createElement('span'); span.textContent = `✓ ${item}`; facts.appendChild(span); }); }
    };
    buttons.forEach((button, index) => {
      button.addEventListener('click', () => activate(button.getAttribute('data-boundary')));
      button.addEventListener('keydown', (event) => {
        if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + buttons.length) % buttons.length;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % buttons.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = buttons.length - 1;
        activate(buttons[next].getAttribute('data-boundary'), true);
      });
    });
  });

  // Homepage contact router. No network request; only prepares the right route.
  const contactCopy = {
    product: ['GENERAL / PRODUCT', 'Start with Aegis.', 'Questions about the current product, Founding Pro, installation, or whether Aegis fits your development workflow.'],
    team: ['TEAM / ENTERPRISE', 'Evaluate Aegis with a real engineering workflow.', 'Talk through team verification, pull-request policy, private deployment requirements, or an organization-level evaluation.'],
    investor: ['FOUNDER', 'Talk directly about the company.', 'Investment and company conversations route directly to the founder channel rather than a generic sales inbox.'],
    partner: ['PARTNERSHIPS', 'Build with Aegis, not around it.', 'Research groups, universities, design partners, and strategic integrations can start with the partnerships channel.'],
    security: ['SECURITY', 'Report a security issue privately.', 'Security disclosures use a dedicated channel. Please avoid opening a public issue for an undisclosed vulnerability.']
  };
  document.querySelectorAll('[data-contact-router]').forEach((root) => {
    const buttons = Array.from(root.querySelectorAll('[data-contact-route]'));
    const label = root.querySelector('[data-contact-label]');
    const title = root.querySelector('[data-contact-title]');
    const copy = root.querySelector('[data-contact-copy]');
    const email = root.querySelector('[data-contact-email]');
    const emailLink = root.querySelector('[data-contact-email-link]');
    const workspace = root.querySelector('[data-contact-workspace]');
    const activate = (button) => {
      const key = button.getAttribute('data-contact-route');
      const data = contactCopy[key] || contactCopy.product;
      const targetEmail = button.getAttribute('data-email') || '';
      const subject = button.getAttribute('data-subject') || 'Aegis enquiry';
      buttons.forEach((item) => {
        const selected = item === button;
        item.classList.toggle('active', selected);
        item.setAttribute('aria-selected', String(selected));
      });
      if (label) label.textContent = data[0];
      if (title) title.textContent = data[1];
      if (copy) copy.textContent = data[2];
      if (email) email.textContent = targetEmail;
      if (emailLink instanceof HTMLAnchorElement) emailLink.href = `mailto:${targetEmail}?subject=${encodeURIComponent(subject)}`;
      if (workspace instanceof HTMLAnchorElement) workspace.href = `/contact?interest=${encodeURIComponent(key)}`;
    };
    buttons.forEach((button) => button.addEventListener('click', () => activate(button)));
  });

  // Command palette (Ctrl/Command + K), local navigation only.
  const palette = document.querySelector('[data-command-palette]');
  if (palette instanceof HTMLElement) {
    const input = palette.querySelector('[data-command-input]');
    const items = Array.from(palette.querySelectorAll('[data-command-item]'));
    const openButtons = document.querySelectorAll('[data-command-open]');
    const closeButtons = palette.querySelectorAll('[data-command-close]');
    let previousFocus = null;
    let activeIndex = 0;
    const visibleItems = () => items.filter((item) => !item.hidden);
    const setActive = (index) => {
      const visible = visibleItems();
      if (!visible.length) return;
      activeIndex = (index + visible.length) % visible.length;
      visible.forEach((item, i) => item.classList.toggle('is-active', i === activeIndex));
    };
    const open = () => {
      previousFocus = document.activeElement;
      palette.hidden = false;
      document.documentElement.classList.add('modal-open');
      if (input instanceof HTMLInputElement) { input.value = ''; input.focus(); }
      items.forEach((item) => { item.hidden = false; item.classList.remove('is-active'); });
      setActive(0);
    };
    const close = () => {
      palette.hidden = true;
      document.documentElement.classList.remove('modal-open');
      if (previousFocus instanceof HTMLElement) previousFocus.focus();
    };
    openButtons.forEach((button) => button.addEventListener('click', open));
    closeButtons.forEach((button) => button.addEventListener('click', close));
    if (input instanceof HTMLInputElement) {
      input.addEventListener('input', () => {
        const query = input.value.trim().toLowerCase();
        items.forEach((item) => { item.hidden = query && !(item.getAttribute('data-search') || item.textContent || '').toLowerCase().includes(query); });
        activeIndex = 0; setActive(0);
      });
      input.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowDown') { event.preventDefault(); setActive(activeIndex + 1); }
        if (event.key === 'ArrowUp') { event.preventDefault(); setActive(activeIndex - 1); }
        if (event.key === 'Enter') { event.preventDefault(); const visible = visibleItems(); if (visible[activeIndex] instanceof HTMLAnchorElement) visible[activeIndex].click(); }
      });
    }
    items.forEach((item) => item.addEventListener('mouseenter', () => { const visible = visibleItems(); setActive(visible.indexOf(item)); }));
    document.addEventListener('keydown', (event) => {
      const shortcut = (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k';
      if (shortcut) { event.preventDefault(); palette.hidden ? open() : close(); }
      if (event.key === 'Escape' && !palette.hidden) close();
    });
  }

  // Release drawer.
  const drawer = document.querySelector('[data-release-drawer]');
  if (drawer instanceof HTMLElement) {
    const openers = document.querySelectorAll('[data-release-open]');
    const closers = drawer.querySelectorAll('[data-release-close]');
    let previousFocus = null;
    const open = () => { previousFocus = document.activeElement; drawer.hidden = false; document.documentElement.classList.add('modal-open'); const closeButton = drawer.querySelector('[data-release-close]'); if (closeButton instanceof HTMLElement) closeButton.focus(); };
    const close = () => { drawer.hidden = true; document.documentElement.classList.remove('modal-open'); if (previousFocus instanceof HTMLElement) previousFocus.focus(); };
    openers.forEach((button) => button.addEventListener('click', open));
    closers.forEach((button) => button.addEventListener('click', close));
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && !drawer.hidden) close(); });
  }


  // Pricing focus follows hover/focus without delaying navigation.
  document.querySelectorAll('[data-pricing-selection]').forEach((summary) => {
    const root = summary.closest('#pricing') || document;
    const links = Array.from(root.querySelectorAll('[data-pricing-plan]'));
    const name = summary.querySelector('[data-pricing-selection-name]');
    const copy = summary.querySelector('[data-pricing-selection-copy]');
    const show = (link) => {
      if (name) name.textContent = link.getAttribute('data-pricing-plan') || '';
      if (copy) copy.textContent = link.getAttribute('data-pricing-copy') || '';
      links.forEach((item) => item.classList.toggle('is-focused', item === link));
    };
    links.forEach((link) => {
      link.addEventListener('mouseenter', () => show(link));
      link.addEventListener('focus', () => show(link));
    });
    const initial = links.find((link) => link.getAttribute('data-pricing-plan') === 'Founding Pro') || links[0];
    if (initial) show(initial);
  });

})();

// Homepage lifecycle rail: a quiet navigation aid, not an animation loop.
(() => {
  const rail = document.querySelector('[data-lifecycle-rail]');
  if (!(rail instanceof HTMLElement)) return;
  const links = Array.from(rail.querySelectorAll('[data-lifecycle-link]'));
  const progress = rail.querySelector('[data-lifecycle-progress]');
  const targets = links
    .map((link) => {
      const id = link.getAttribute('data-lifecycle-link');
      return id ? { id, link, section: document.getElementById(id) } : null;
    })
    .filter((item) => item && item.section);
  const hero = document.getElementById('top');

  const update = () => {
    const y = window.scrollY + window.innerHeight * 0.36;
    rail.classList.toggle('is-visible', window.scrollY > Math.max(260, (hero?.offsetHeight || 700) * .55));
    let activeIndex = 0;
    targets.forEach((item, index) => {
      if (item.section.offsetTop <= y) activeIndex = index;
    });
    targets.forEach((item, index) => item.link.classList.toggle('active', index === activeIndex));
    if (progress instanceof HTMLElement && targets.length > 1) {
      progress.style.height = `${(activeIndex / (targets.length - 1)) * 100}%`;
    }
  };
  window.addEventListener('scroll', update, { passive: true });
  window.addEventListener('resize', update, { passive: true });
  update();
})();
