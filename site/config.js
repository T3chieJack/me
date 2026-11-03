const SITE_LAN_HOST = 'YOUR_SERVER_IP';
const SITE_PUBLIC_API = '';
const SITE_TURNSTILE_KEY = '0x4AAAAAAFykwlhK7GE-auCR';
const LIVE_YEAR_URL = '';

function siteApi() {
    const host = window.location.hostname;
    if (host === SITE_LAN_HOST) return window.location.origin;
    if (host === 'localhost' || host === '127.0.0.1') return `https://${SITE_LAN_HOST}`;
    return SITE_PUBLIC_API;
}

function turnstileKey() {
    const host = window.location.hostname;
    return host === SITE_LAN_HOST || host === 'localhost' || host === '127.0.0.1' ? '' : SITE_TURNSTILE_KEY;
}

const SITE_API = siteApi();
const TURNSTILE_KEY = turnstileKey();
