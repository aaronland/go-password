# go-password

## bcrypt

```
bcrypt:///?password=PLAINTEXT[&salt=SALT][&pepper=SECRET][&cost=N]
bcrypt:///?digest=DIGEST&salt=SALT[&pepper=SECRET]
```

* `password` – URL-escaped plain text (minimum 8 characters). `bcrypt://PLAINTEXT` is also accepted if the password has no URI-significant characters; otherwise an error is returned.
* `salt` – generated with `crypto/rand` if omitted. It is serialized by `String()` next to the digest, so it is **not** a secret. A `digest` requires its `salt` (or `pepper`).
* `pepper` – optional secret HMAC key, never serialized. Store it separately from the digests and supply it again when loading them. If omitted the salt is used as the HMAC key (legacy behaviour).
* `cost` – bcrypt cost, default 12.

`String()` returns `digest` and `salt` only; treat it as sensitive and avoid logging it.
