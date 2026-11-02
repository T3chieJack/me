const ANALYTICS_PING_MS = 15000;

(() => {
    if (!SITE_API || navigator.globalPrivacyControl) return;
    const endpoint = `${SITE_API}/api/collect`;

    const visitId = [...crypto.getRandomValues(new Uint8Array(16))]
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

    function send(event) {
        const body = new Blob([JSON.stringify({ v: visitId, ...event })], { type: 'text/plain' });
        navigator.sendBeacon(endpoint, body);
    }

    function clickLabel(element) {
        const text = element.querySelector('.project-name')?.textContent
            || element.querySelector('img')?.alt
            || element.textContent;
        return text.replace(/[^A-Za-z0-9 ._:/-]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 64);
    }

    send({ t: 'view', p: window.location.pathname });

    setInterval(() => {
        if (document.visibilityState === 'visible') send({ t: 'ping' });
    }, ANALYTICS_PING_MS);

    document.addEventListener('visibilitychange', () => {
        send({ t: document.visibilityState === 'visible' ? 'ping' : 'leave' });
    });

    window.addEventListener('pagehide', () => send({ t: 'leave' }));

    document.addEventListener('click', (event) => {
        const element = event.target.closest('a, button');
        const label = element && clickLabel(element);
        if (label) send({ t: 'click', l: label });
    });
})();
