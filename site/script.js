const SCROLL_DURATION = 1000;
const INERTIA_GAP = 200;

const sections = [...document.querySelectorAll('.hero, .content')];
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
const finePointer = matchMedia('(pointer: fine)').matches;

let animating = false;
let lastWheel = 0;

const easeInOutCubic = (t) => (t < 0.5 ? 4 * t ** 3 : 1 - (-2 * t + 2) ** 3 / 2);

function targetFor(direction) {
    const y = window.scrollY;
    const height = window.innerHeight;
    const tops = sections.map((section) => section.offsetTop);

    if (direction > 0) {
        const next = tops.find((top) => top > y + 1);
        return next !== undefined && next <= y + height + 1 ? next : null;
    }

    const previous = tops.filter((top) => top < y - 1).pop();
    return previous !== undefined && y - previous <= height + 1 ? previous : null;
}

function glideTo(target) {
    const start = window.scrollY;
    const startTime = performance.now();
    animating = true;

    function step(now) {
        const progress = Math.min((now - startTime) / SCROLL_DURATION, 1);
        window.scrollTo(0, start + (target - start) * easeInOutCubic(progress));

        if (progress < 1) {
            requestAnimationFrame(step);
        } else {
            animating = false;
        }
    }

    requestAnimationFrame(step);
}

if (finePointer && !reducedMotion) {
    window.addEventListener('wheel', (event) => {
        if (event.ctrlKey) return;

        const textarea = event.target.closest?.('textarea');
        if (textarea && textarea.scrollHeight > textarea.clientHeight) return;

        const now = performance.now();
        const stillInertia = now - lastWheel < INERTIA_GAP;
        lastWheel = now;

        if (animating) {
            event.preventDefault();
            return;
        }

        const target = targetFor(Math.sign(event.deltaY));
        if (target === null) return;

        event.preventDefault();
        if (!stillInertia) glideTo(target);
    }, { passive: false });

    window.addEventListener('keydown', (event) => {
        if (event.target.closest?.('input, textarea, button')) return;

        const directions = { ArrowDown: 1, PageDown: 1, ArrowUp: -1, PageUp: -1 };
        const direction = event.key === ' ' ? (event.shiftKey ? -1 : 1) : directions[event.key];
        if (!direction) return;

        const target = animating ? null : targetFor(direction);
        if (animating || target !== null) event.preventDefault();
        if (target !== null) glideTo(target);
    });
}

document.querySelectorAll('a[href^="#"]').forEach((link) => {
    link.addEventListener('click', (event) => {
        const destination = document.querySelector(link.getAttribute('href'));
        if (!destination) return;

        event.preventDefault();
        if (finePointer && !reducedMotion) {
            if (!animating) glideTo(destination.offsetTop);
        } else {
            destination.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth' });
        }
        destination.focus({ preventScroll: true });
    });
});

const nextCue = document.querySelector('.next-cue');
const nextCueLabel = nextCue.querySelector('.next-cue-label');

function updateNextCue() {
    const middle = window.scrollY + window.innerHeight / 2;
    const currentIndex = sections.filter((section) => section.offsetTop <= middle).length - 1;
    const next = sections[currentIndex + 1];

    nextCue.classList.toggle('is-hidden', !next);
    nextCue.tabIndex = next ? 0 : -1;
    if (next) {
        nextCue.setAttribute('href', `#${next.id}`);
        nextCueLabel.textContent = `Next: ${next.dataset.label}`;
    }
}

window.addEventListener('scroll', updateNextCue, { passive: true });
window.addEventListener('resize', updateNextCue);
updateNextCue();

const stackLogos = [...document.querySelectorAll('.marquee-track img')];
stackLogos.forEach((logo, index) => {
    logo.title = stackLogos[index % (stackLogos.length / 2)].alt;
});

function blogRow(post) {
    const row = document.createElement('li');
    const link = document.createElement('a');
    const name = document.createElement('span');
    const date = document.createElement('time');
    const summary = document.createElement('span');

    link.className = 'project';
    link.href = `posts/${encodeURIComponent(post.slug)}.html`;
    name.className = 'project-name';
    name.textContent = post.title;
    date.className = 'project-tech';
    date.dateTime = post.iso;
    date.textContent = post.date;
    link.append(name, date);
    if (post.summary) {
        summary.className = 'project-description';
        summary.textContent = post.summary;
        link.append(summary);
    }
    row.append(link);
    return row;
}

async function showBlogPosts() {
    const response = await fetch('posts/posts.json', { cache: 'no-cache' }).catch(() => null);
    if (!response?.ok) return;

    const feed = await response.json().catch(() => null);
    if (!feed?.posts?.length) return;

    document.querySelector('.blog-empty').hidden = true;
    const list = document.querySelector('.blog-list');
    list.append(...feed.posts.map(blogRow));
    list.hidden = false;
    document.querySelector('.blog-all').hidden = feed.total <= feed.posts.length;
}

showBlogPosts();

async function showLiveYear() {
    let year = new Date().getFullYear();

    if (LIVE_YEAR_URL) {
        try {
            const response = await fetch(LIVE_YEAR_URL, { cache: 'no-store' });
            const text = response.ok ? (await response.text()).trim() : '';
            if (/^\d{4}$/.test(text)) year = text;
        } catch {
            year = new Date().getFullYear();
        }
    }

    document.querySelectorAll('[data-live-year]').forEach((element) => {
        element.textContent = year;
    });
}

showLiveYear();

const contactForm = document.querySelector('.contact-form');
const contactStatus = contactForm.querySelector('.form-status');
const contactSubmit = contactForm.querySelector('.contact-submit');

function showStatus(message, isError = false) {
    contactStatus.textContent = message;
    contactStatus.classList.toggle('is-error', isError);
}

contactForm.addEventListener('input', () => showStatus(''));

const CONTACT_ERRORS = {
    400: 'Please check your name, email address and message, then try again.',
    403: 'The security check did not pass. Please try again.',
    429: 'Too many messages have been sent recently. Please try again later.',
    503: 'The contact form is not available right now. Please try again later.',
};

const TURNSTILE_ERROR = 'The security check could not load. Please turn off any content blocker for this site, then reload the page.';
let turnstileWidget;

function loadTurnstile() {
    window.onTurnstileLoad = () => {
        turnstileWidget = window.turnstile.render('.turnstile-slot', {
            sitekey: TURNSTILE_KEY,
            action: 'contact',
            theme: 'dark',
            appearance: 'interaction-only',
            'error-callback': () => showStatus(TURNSTILE_ERROR, true),
        });
    };

    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit';
    script.async = true;
    script.onerror = () => showStatus(TURNSTILE_ERROR, true);
    document.head.append(script);
}

if (TURNSTILE_KEY) {
    const turnstileTrigger = new IntersectionObserver((entries, observer) => {
        if (!entries.some((entry) => entry.isIntersecting)) return;
        observer.disconnect();
        loadTurnstile();
    }, { threshold: 0.1 });
    turnstileTrigger.observe(contactForm);
}

contactForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    if (!SITE_API) {
        showStatus('The contact form is not available right now. Please try again later.', true);
        return;
    }

    const fields = Object.fromEntries(new FormData(contactForm));
    if (TURNSTILE_KEY && !fields['cf-turnstile-response']) {
        showStatus('Please finish the security check, then send your message again.');
        return;
    }

    contactSubmit.disabled = true;
    showStatus('Sending...');

    try {
        const response = await fetch(`${SITE_API}/api/contact`, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: JSON.stringify(fields),
        });

        if (response.ok) {
            contactForm.reset();
            showStatus('Thanks, your message has been sent.');
        } else {
            showStatus(CONTACT_ERRORS[response.status] || 'Your message could not be sent. Please try again in a moment.', true);
        }
    } catch {
        showStatus('Your message could not be sent. Please try again in a moment.', true);
    } finally {
        contactSubmit.disabled = false;
        if (turnstileWidget !== undefined) window.turnstile.reset(turnstileWidget);
    }
});
