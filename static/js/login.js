/**
 * Generate options for the credential request API call (WebAuthn).
 */
function generateRequestOptions(credentials, challenge) {

    let allowCredentials = credentials.map(credential => ({
        id: Uint8Array.from(atob(credential), c => c.charCodeAt(0)),
        type: 'public-key',
    }));

    const publicKeyCredentialRequestOptions = {
        challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
        allowCredentials: allowCredentials,
        timeout: 60 * 1000,
    };
    return publicKeyCredentialRequestOptions;
}


/**
 * Encode an ArrayBuffer into a base64 string.
 *
 * The official example does something much more complicated, so perhaps I am missing something here.
 */
function bufferEncode(value) {
    return btoa(String.fromCharCode(...value));
}


async function submitForm(form) {
    // TODO validation
    const challenge = form.elements['challenge'].value;
    const userName = form.elements['user_name'].value;

    const credentials = await fetch('/credentials?user_name=' + userName, {
        method: 'GET',
        headers: {'Content-Type': 'application/json; charset=utf-8'},
    }).then(r => r.json());

    const publicKeyCredentialRequestOptions = generateRequestOptions(credentials, challenge);
    const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
    });

    let authData = new Uint8Array(assertion.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
    let rawId = new Uint8Array(assertion.rawId);
    let sig = new Uint8Array(assertion.response.signature);
    let userHandle = new Uint8Array(assertion.response.userHandle);

    await fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: JSON.stringify({
            id: assertion.id,
            userName: userName,
            rawId: bufferEncode(rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferEncode(authData),
                clientDataJSON: bufferEncode(clientDataJSON),
                signature: bufferEncode(sig),
                userHandle: bufferEncode(userHandle),
            },
        }),
    });
}

(function() {
    let form = document.getElementById('login');
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        submitForm(form);
    });
})();