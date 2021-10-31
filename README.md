Self-study for WebAuthn. How would I build a passwordless web app?

# Plan
- [x] start simple flask app
- [x] implement basic db layer
- [x] store challenge in a sensible place
- [x] create user (register)
- [x] login user (authenticate)
- [x] add support for multiple devices

# Questions
### Do we have to pre-generate user ID, before the user hits "register"?
Sorta. The API call that asks the authenticator to generate a credential for the site requires a user ID. However, this
user ID could be deterministically generated from the proposed username. There is nothing requiring that the user ID is
pre-generated in your database. However, if the proposed user name (and hence user ID) turns out to be not unique, then
the PUT call to `/register` would fail. I am not sure if the authenticator stores all proposed user IDs across all RPs;
this might be a small issue.

Follow-up question: how many RPs can a Yubikey support? Is there a limit? What about other manufacturers?

### Can the same authenticator be used for multiple users?
I don't see why not, as long as the public keys and credential IDs are unique. On the server-side, we might not even
be aware that two credentials are from the same authenticator.

Follow-up question: are credential IDs from the same Yubikey expected to be unique? What about other manufacturers?

### Could the API be exploited to harvest usernames, or somehow figure out who is (or isn't) a user?
- `/hash_user_id` is a deterministic hash function that does not leak any information.
- `/list_credentials` can be written to just return fake credential ID even if the given user name does not exist.

Note that the naïve implementation is probably susceptible to a timing attack. We may have to inject random milliseconds
of delay in both the positive and negative paths.

### How can a person have multiple accounts at the Relying Party?
- different user IDs and name
- `display name` does not have to be unique
- authenticators can be shared/reused

From https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-displayname,
> Note: the user handle ought not be a constant value across different accounts, even for non-discoverable credentials,
> because some authenticators always create discoverable credentials. Thus a constant user handle would prevent a user
> from using such an authenticator with more than one account at the Relying Party.

# Ref
https://w3c.github.io/webauthn/#sctn-cryptographic-challenges