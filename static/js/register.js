/**
 * Generate options for the credential creation API call (WebAuthn).
 */
function generateCreationOptions(userId, userName, displayName, challenge) {
    const publicKeyCredentialCreationOptions = {
        challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
        rp: {
            name: location.host,
            id: location.hostname,
        },
        user: {
            id: Uint8Array.from(userId, c => c.charCodeAt(0)),
            name: userName,
            displayName: displayName,
        },
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
        timeout: 60 * 1000,
    };
    return publicKeyCredentialCreationOptions;
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

    // https://w3c.github.io/webauthn/#dictdef-publickeycredentialentity
    /* It is intended only for display, i.e., aiding the user in determining the difference between user accounts with
     * similar displayNames. */
    const userName = form.elements['user_name'].value;

    /* A human-palatable name for the user account, intended only for display. */
    const displayName = form.elements['display_name'].value;

    const userId = await fetch('/hash_user_id?user_name=' + userName, {
        method: 'GET',
        headers: {'Content-Type': 'application/json; charset=utf-8'},
    }).then(r => r.json());

    const pubKeyOptions = generateCreationOptions(userId, userName, displayName, challenge);
    const credential = await navigator.credentials.create({
        publicKey: pubKeyOptions,
    });
    // TODO error handling

    const attestationObject = new Uint8Array(credential.response.attestationObject);
    const clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
    const rawId = new Uint8Array(credential.rawId);

    await fetch('/register', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: JSON.stringify({
            id: credential.id,
            rawId: bufferEncode(rawId),
            type: credential.type,
            userId: userId,
            userName: userName,
            displayName: displayName,
            response: {
                attestationObject: bufferEncode(attestationObject),
                clientDataJSON: bufferEncode(clientDataJSON),
            },
        }),
    });
    // TODO error handling

}

(function() {
    let form = document.getElementById('signup');
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        submitForm(form);
    });
})();
