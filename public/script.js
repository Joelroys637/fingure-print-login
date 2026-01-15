const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

async function register() {
    const usernameInput = document.getElementById('username');
    const status = document.getElementById('status');
    const username = usernameInput.value;

    if (!username) {
        status.innerText = 'Please enter a username.';
        status.className = 'status error';
        return;
    }

    status.innerText = 'Initializing...';
    status.className = 'status';

    try {
        // 1. Get options
        const resp = await fetch('/register/challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(`Server Error: ${text}`);
        }

        const options = await resp.json();

        // 2. Start Registration (Handled by library to convert options correctly)
        status.innerText = 'Scan your fingerprint now...';
        status.classList.add('scanning');

        let attResp;
        try {
            attResp = await startRegistration(options);
        } catch (e) {
            if (e.name === 'InvalidStateError') {
                throw new Error('Authenticator already registered for this user.');
            } else {
                throw e;
            }
        }

        status.classList.remove('scanning');
        status.innerText = 'Verifying...';

        // 3. Verify
        const verificationResp = await fetch('/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                response: attResp
            })
        });

        const verificationJSON = await verificationResp.json();

        if (verificationJSON.verified && verificationJSON.verified === true) {
            status.innerText = 'Success! Fingerprint registered.';
            status.className = 'status success';
            setTimeout(() => window.location.href = '/', 2000);
        } else {
            status.innerText = `Oh no, something went wrong! Response: ${JSON.stringify(verificationJSON)}`;
            status.className = 'status error';
        }

    } catch (e) {
        status.classList.remove('scanning');
        status.innerText = e.message || 'An error occurred';
        status.className = 'status error';
        console.error(e);
    }
}

async function login() {
    const status = document.getElementById('status');
    status.innerText = 'Initializing authentication...';
    status.className = 'status';

    try {
        // 1. Get options
        const resp = await fetch('/login/challenge', {
            method: 'POST'
        });

        const options = await resp.json();

        status.innerText = 'Scan your fingerprint...';
        status.classList.add('scanning');

        // 2. Start Auth
        const asseResp = await startAuthentication(options);

        status.classList.remove('scanning');
        status.innerText = 'Verifying...';

        // 3. Verify
        // Add the challenge we received back to the body?
        // Note: The library/browser puts the challenge in clientDataJSON which is part of asseResp.
        // We just need to send asseResp to server.

        const verificationResp = await fetch('/login/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                response: asseResp
            })
        });

        const verificationJSON = await verificationResp.json();

        if (verificationJSON.verified) {
            status.innerText = `Login Successful! Welcome ${verificationJSON.username || ''}`;
            status.className = 'status success';
        } else {
            status.innerText = 'Authentication failed. Please try again.';
            status.className = 'status error';
        }

    } catch (e) {
        status.classList.remove('scanning');
        status.innerText = e.message || 'An error occurred during login';
        status.className = 'status error';
        console.error(e);
    }
}
