/* Native WebAuthn ceremonies. No credentials or protocol payloads are logged. */
(() => {
    'use strict';
    const config = window.amsecPasskeys;
    const profile = document.getElementById('amsec-passkeys');
    const login = document.getElementById('amsec-passkey-signin');
    if (!config || (!profile && !login)) return;
    const root = profile || login.closest('.amsec-passkey-login');
    const status = root.querySelector('.amsec-passkey-status');
    const buttons = [...root.querySelectorAll('button')];
    const supported = window.isSecureContext && window.PublicKeyCredential && navigator.credentials;
    const field = name => document.getElementById('amsec-passkey-' + name);
    const decode = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
    const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const request = async (action, fields = {}) => {
        const body = new FormData();
        body.set('action', 'amsec_passkey_' + action);
        Object.entries(fields).forEach(([key, value]) => body.set(key, value));
        const response = await fetch(config.endpoint, {method: 'POST', credentials: 'same-origin', body, cache: 'no-store'});
        const result = await response.json();
        if (!response.ok || result.success !== true) throw new Error(config.failed);
        return result.data;
    };
    const envelope = (credential, registration) => {
        if (!credential || credential.type !== 'public-key') throw new Error(config.failed);
        const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
        if (registration) response.attestationObject = encode(credential.response.attestationObject);
        else {
            if (!credential.response.userHandle) throw new Error(config.failed);
            response.authenticatorData = encode(credential.response.authenticatorData);
            response.signature = encode(credential.response.signature);
            response.userHandle = encode(credential.response.userHandle);
        }
        return JSON.stringify({id: encode(credential.rawId), rawId: encode(credential.rawId), type: credential.type, response});
    };
    let busy = false;
    const run = async operation => {
        if (busy) return;
        busy = true;
        const disabled = buttons.map(button => button.disabled);
        buttons.forEach(button => { button.disabled = true; });
        status.textContent = config.working;
        try { await operation(); }
        catch (error) { status.textContent = error.message === config.approval ? config.approval : config.failed; }
        finally {
            if (profile) {
                field('password').value = '';
                field('factor').value = '';
                field('confirm').checked = false;
            } else {
                const factor = document.getElementById('amsec-otp');
                if (factor) factor.value = '';
            }
            buttons.forEach((button, index) => { button.disabled = disabled[index]; });
            busy = false;
        }
    };
    if (!supported) {
        status.textContent = config.unsupported;
        if (login) login.disabled = true;
        if (profile) field('add').disabled = true;
    }
    if (profile) {
        const approval = () => {
            if (!field('password').value || !field('confirm').checked) throw new Error(config.approval);
            return {_wpnonce: field('nonce').value, password: field('password').value, factor: field('factor').value, confirm: '1'};
        };
        field('add').addEventListener('click', () => run(async () => {
            const approved = approval();
            const label = field('label').value.trim();
            if (!label || new TextEncoder().encode(label).length > 80) throw new Error(config.failed);
            const begun = await request('enroll_begin', approved);
            field('password').value = ''; field('factor').value = '';
            const options = begun.publicKey;
            options.challenge = decode(options.challenge);
            options.user.id = decode(options.user.id);
            options.excludeCredentials = options.excludeCredentials.map(item => ({...item, id: decode(item.id)}));
            const credential = await navigator.credentials.create({publicKey: options});
            await request('enroll_finish', {_wpnonce: approved._wpnonce, ticket: begun.ticket, label, payload: envelope(credential, true)});
            status.textContent = config.saved;
            window.location.reload();
        }));
        root.querySelectorAll('.amsec-passkey-remove').forEach(button => button.addEventListener('click', () => run(async () => {
            await request('remove', {...approval(), credential: button.dataset.credential});
            status.textContent = config.saved;
            window.location.reload();
        })));
    }
    if (login) login.addEventListener('click', () => run(async () => {
        const begun = await request('login_begin');
        begun.publicKey.challenge = decode(begun.publicKey.challenge);
        const credential = await navigator.credentials.get({publicKey: begun.publicKey});
        const result = await request('login_finish', {ticket: begun.ticket, factor: '', payload: envelope(credential, false)});
        const redirect = new URL(result.redirect);
        if (redirect.origin !== window.location.origin) throw new Error(config.failed);
        window.location.assign(redirect.href);
    }));
})();
