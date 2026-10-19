# TIP-1151 diagrams

All five diagrams for TIP-1151 (signed deposit authorizations for zone portals). Each `.excalidraw`
file is the editable source: open https://excalidraw.com, choose **Open** (or drag the file onto
the canvas), edit, and export PNG or SVG. The rendered PNG links below are public.

| # | Diagram | Source | Rendered |
|---|---|---|---|
| 1 | Moving parts | `deposit-auth-overview.excalidraw` | [PNG](https://ampcode.com/user-content/artifacts/87e7f6d3836b8310cda9dd013d1a6e61777594383cb6b2aa6dc96ecb951af315-file.png) |
| 2 | How a new user gets in: today vs. signed authorizations | `deposit-auth-modes.excalidraw` | [PNG](https://ampcode.com/user-content/artifacts/d3e0dd181770d7b32ee8947bcb1072505fc04c8742be926e902373d287c72f67-file.png) |
| 3 | What `depositAuthorized` checks, in order | `deposit-auth-portal-checks.excalidraw` | [PNG](https://ampcode.com/user-content/artifacts/6af5f408d64b0ce0109ace252edd19c61ed806c2b887d140c47add87945235d8-file.png) |
| 4 | OIDC + enclave authorizer (whiteboard flow) | `deposit-auth-oidc-tee.excalidraw` | [PNG](https://ampcode.com/user-content/artifacts/88f7bd71b966d42f420989d59422aabaf502b42dbe96918b3c80baf3a8902270-file.png) |
| 5 | Change set: what changed where | `deposit-auth-change-set.excalidraw` | [PNG](https://ampcode.com/user-content/artifacts/7a87ca79c9535509c67de6871c777088949838dd716b0bc4dd4eda22d9326e23-file.png) |

---

## 1. Moving parts

The admin registers an authorizer key and turns the mode on (step 0). The depositor asks the
operator's authorizer for permission (1), the authorizer applies policy and signs (2) and returns
the authorization (3), and the depositor calls `depositAuthorized` (4). The portal recovers the
signer through TIP-1020 (5), enqueues the deposit with the unchanged encoding (6), and the sequencer
and `ZoneInbox` process it exactly as before (7, 8).

![Moving parts](https://ampcode.com/user-content/artifacts/87e7f6d3836b8310cda9dd013d1a6e61777594383cb6b2aa6dc96ecb951af315-file.png)

## 2. How a new user gets in

Closed access needs an admin transaction per user and publishes the customer list. Open access has
no policy, and the zone must process every deposit. Signed authorizations apply policy offchain with
no onchain transaction, and the zone-side path stays the same.

![How a new user gets in](https://ampcode.com/user-content/artifacts/d3e0dd181770d7b32ee8947bcb1072505fc04c8742be926e902373d287c72f67-file.png)

## 3. What `depositAuthorized` checks

The portal's checks in execution order, with the error each failure reverts with. The nonce is
consumed before the shared deposit checks, and the deposit is queued through the same internal path
as `deposit`.

![What depositAuthorized checks](https://ampcode.com/user-content/artifacts/6af5f408d64b0ce0109ace252edd19c61ed806c2b887d140c47add87945235d8-file.png)

## 4. OIDC + enclave authorizer

The whiteboard flow. The user signs in with an OIDC provider (1) and sends the ID token with the
deposit request to an enclave authorizer (2). The enclave verifies the token, binds the subject to a
Tempo address in its encrypted database (3), and signs (4). The portal only sees an address with the
`DepositAuthorizer` role (5). The admin registers the enclave key once after checking its
attestation (0).

![OIDC + enclave authorizer](https://ampcode.com/user-content/artifacts/88f7bd71b966d42f420989d59422aabaf502b42dbe96918b3c80baf3a8902270-file.png)

## 5. Change set

Every component the implementation touches, grouped into consensus (Tempo L1 portal runtime),
offchain zone node, and SDK, tooling, and docs, with the test coverage underneath.

![Change set](https://ampcode.com/user-content/artifacts/7a87ca79c9535509c67de6871c777088949838dd716b0bc4dd4eda22d9326e23-file.png)
