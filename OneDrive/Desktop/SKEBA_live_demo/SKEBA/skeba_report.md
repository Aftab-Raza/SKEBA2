# Formal Security Analysis of SKEBA

Source analyzed: `SKEBA_fixed.zip`

Implementation files inspected:

- `protocol/registration.py`
- `protocol/login.py`
- `protocol/access_control.py`
- `tests/test_full_protocol.py`

## 1. Protocol Summary

The implementation has four main phases.

### Setup

The authentication server `S` generates a Saber KEM key pair:

- public key: `pk_S`
- private key: `sk_S`

The public key is stored in the user's smart card during registration.

### Registration

The user `U_i` chooses random `r_i` and computes:

```text
beta_i = H1(r_i || ID_i || PWD_i)
```

The server chooses a registration secret `rs` and computes:

```text
gamma_i  = H1(rs || ID_i)
lambda_i = beta_i XOR gamma_i
```

The smart card stores:

```text
lambda_i, eta_i, zeta_i, pk_S
```

where:

```text
eta_i  = H3(ID_i || PWD_i) XOR r_i
zeta_i = H2(H3(ID_i || PWD_i) || r_i || gamma_i)
```

### Login and Mutual Authentication

The smart card locally checks the password by recomputing `zeta_i`.

Then the user creates a Saber KEM encapsulation:

```text
(CT, K) = Saber.Encaps(pk_S)
```

The user encrypts the login payload using AES-GCM under `K`:

```text
payload = Enc_K(ID_i, T1, rt)
```

The user sends:

```text
M1: U_i -> S : CT, Enc_K(ID_i, T1, rt)
```

The server decapsulates:

```text
K = Saber.Decaps(CT, sk_S)
```

Then it decrypts the payload, looks up `ID_i`, recomputes `gamma_i`, and returns:

```text
M2: S -> U_i : v = H1(K || gamma_i || T1 || rt)
```

The user verifies `v`.

### Access Control

After login, the server issues a temporary identity `ID_it` and sends a masked response to the user. The medical device receives the corresponding grant from the server. The user proves possession of `ID_it` to the device using:

```text
pi = H1(ID_it || T4)
```

The user and device derive:

```text
K_t = H1(ID_it || K || T3)
```

## 2. Important Finding

The current implementation does not prove the user's identity to the server during login.

The smart card verifies the password locally, but the server never receives a value proving that the sender knows `PWD_i`, `r_i`, or `gamma_i`. In `protocol/login.py`, the server accepts a login request after decrypting:

```text
ID_i, T1, rt
```

under the KEM-derived key `K`. However, any network attacker can generate a valid KEM encapsulation using the public key `pk_S`.

Therefore, the current design has a user impersonation weakness.

## 3. Concrete Attack on Current Login

Adversary `A` wants to impersonate user `ID_i`.

1. `A` obtains the public server key `pk_S`.
2. `A` runs:

```text
(CT_A, K_A) = Saber.Encaps(pk_S)
```

3. `A` sends:

```text
M1*: A -> S : CT_A, Enc_KA(ID_i, T1, rt)
```

4. The server decapsulates `CT_A`, obtains `K_A`, decrypts the payload, finds `ID_i`, and marks the session as authenticated.
5. The server returns:

```text
v = H1(K_A || gamma_i || T1 || rt)
```

6. Even if `A` cannot verify `v`, the server-side session is already authenticated.
7. If the server issues access under `K_A`, `A` can decrypt the access response, recover `ID_it`, and send:

```text
pi = H1(ID_it || T4)
```

to the medical device.

Attack success probability is essentially 1, assuming the attacker knows or guesses a valid `ID_i` and uses a fresh timestamp.

## 4. ROR Model Analysis

### ROR Participants

- `U_i`: user
- `SC_i`: smart card
- `S`: authentication server
- `D_j`: medical IoT device
- `A`: probabilistic polynomial-time adversary

### ROR Queries

The adversary is allowed the standard real-or-random queries:

```text
Execute(U_i, S, D_j)
Send(P, message)
Reveal(session)
CorruptSmartCard(SC_i)
Test(session)
Hash(input)
```

### Security Goal

For a fresh session, the adversary should not distinguish the real session key from a random key:

```text
Adv_A = |2 * Pr[A wins Test] - 1|
```

A secure protocol must make `Adv_A` negligible.

### ROR Result for Current Implementation

The current implementation cannot be proven secure in the ROR model.

Reason: an adversary can create a server-side session for victim identity `ID_i` by running Saber encapsulation with public key `pk_S`. The server accepts because the login request contains no user authenticator.

In ROR terms, the adversary uses a `Send` query:

```text
Send(S, CT_A, Enc_KA(ID_i, T1, rt))
```

The server accepts and stores `K_A` as the authenticated session key for `ID_i`. Since `A` created `K_A`, the adversary knows the test-session key.

Therefore:

```text
Pr[A wins Test] = 1
Adv_A = 1
```

This is not negligible. The current protocol fails ROR session-key security and user authentication.

## 5. Stolen Smart Card Observation

The smart card stores:

```text
lambda_i, eta_i, zeta_i
```

If an attacker steals the smart card and knows or guesses `ID_i`, then for each password guess `PWD*`, the attacker can compute:

```text
r*      = eta_i XOR H3(ID_i || PWD*)
beta*   = H1(r* || ID_i || PWD*)
gamma*  = lambda_i XOR beta*
zeta*   = H2(H3(ID_i || PWD*) || r* || gamma*)
```

Then the attacker checks whether:

```text
zeta* == zeta_i
```

This gives an offline password guessing test. Therefore, the implementation should not claim resistance to offline password guessing under smart-card compromise unless the password space is assumed high entropy or the smart-card storage design is changed.

## 6. Minimal Fix Needed for ROR Security

The login request must include a user-to-server authenticator that only the legitimate smart card/user can compute.

A minimal symbolic fix is:

```text
auth_U = H1(K || gamma_i || T1 || rt || "U->S")
```

Then send:

```text
M1: U_i -> S : CT, Enc_K(ID_i, T1, rt, auth_U)
```

The server verifies:

```text
auth_U == H1(K || gamma_i || T1 || rt || "U->S")
```

Only after this check should the server mark the session authenticated.

The server response should use domain separation:

```text
auth_S = H1(K || gamma_i || T1 || rt || "S->U")
```

This prevents reflection between user proof and server proof.

## 7. ROR Proof Sketch for the Repaired Login

This proof applies to the repaired protocol, not to the current implementation.

### Game G0: Real Protocol

`G0` is the real execution of the repaired protocol.

```text
Adv_A = |2 * Pr[Succ_0] - 1|
```

### Game G1: Passive Eavesdropping

The adversary observes:

```text
CT, Enc_K(ID_i, T1, rt, auth_U), auth_S
```

Under Saber KEM security and AEAD confidentiality, the adversary cannot learn `K`, `rt`, or `auth_U`.

The difference between `G0` and `G1` is bounded by:

```text
Adv_Saber_KEM + Adv_AEAD
```

### Game G2: Active Login Forgery

To impersonate `U_i`, the adversary must produce:

```text
auth_U = H1(K || gamma_i || T1 || rt || "U->S")
```

Without knowing `gamma_i`, the best attack is to guess the hash output.

If `H1` has `l_H` bits, the probability of a successful forgery is bounded by:

```text
q_send / 2^l_H
```

Hash collisions are bounded by:

```text
q_H^2 / 2^(l_H + 1)
```

### Game G3: Session Key Secrecy

The session key `K` is generated by Saber encapsulation and protected by the KEM assumption. If the adversary does not break Saber, reveal the session, or forge `auth_U`, then `K` is indistinguishable from random.

### Game G4: Device Access Key

The device key is:

```text
K_t = H1(ID_it || K || T3)
```

The temporary identity `ID_it` and timestamp `T3` are delivered under the authenticated server-user session and through the assumed secure server-device grant channel.

If `K` remains secret and `ID_it` is fresh, then `K_t` is pseudorandom.

### Final Bound

For the repaired protocol:

```text
Adv_A <= Adv_Saber_KEM
       + Adv_AEAD
       + q_send / 2^l_H
       + q_H^2 / 2^(l_H + 1)
       + q_ID / 2^l_ID
       + Adv_password
```

where:

- `Adv_Saber_KEM` is the advantage of breaking Saber KEM.
- `Adv_AEAD` is the advantage of breaking AES-GCM confidentiality/integrity.
- `q_send` is the number of active send attempts.
- `q_H` is the number of hash queries.
- `q_ID` is the number of guesses for the temporary identity.
- `l_ID` is the bit length of the temporary identity.
- `Adv_password` must include offline guessing risk if the smart card is compromised.

If Saber, AES-GCM, and SHA3 are secure, and if smart-card compromise is excluded or redesigned to prevent offline verification, then the repaired protocol achieves mutual authentication and session-key secrecy in the ROR model.

## 8. Scyther Analysis Plan

Two Scyther models are provided:

1. `skeba_current_protocol.spdl`
   - Models the current implementation.
   - Expected result: Scyther should report authentication/agreement attacks against the server role because the server accepts without a client authenticator.

2. `skeba_repaired_protocol.spdl`
   - Models the repaired login message with `auth_U`.
   - Expected result under symbolic assumptions: Scyther should verify secrecy and agreement claims.

## 9. How to Explain This to a Supervisor

Use the following explanation:

The implementation uses strong cryptographic primitives, but formal analysis checks whether the primitives are connected correctly. In the current login phase, the user verifies the password only locally on the smart card. The server receives an encrypted identity and timestamp, but it does not receive any proof that the sender knows the user's password-derived secret or registration secret. Since the server public key is public, an attacker can create a valid KEM ciphertext and encrypted payload for any known user identity. Therefore, the server can be tricked into authenticating an attacker as that user.

The ROR model shows this as a session-key security failure because the attacker creates the key accepted by the server. The Scyther model represents the same weakness as an authentication/agreement failure. Adding a user authenticator `auth_U = H1(K || gamma_i || T1 || rt || "U->S")` fixes the missing proof because only the legitimate user/smart card and the server can compute `gamma_i`.

## 10. Verification Status

Local implementation test attempted:

```text
python tests/test_full_protocol.py
```

Result:

```text
ModuleNotFoundError: No module named 'Crypto'
ModuleNotFoundError: No module named 'cryptography'
```

The local Python environment is missing dependencies from `requirements.txt`, especially `pycryptodome` and `cryptography`.

Scyther command-line tool status:

```text
scyther
```

Result: not installed in the current environment.

