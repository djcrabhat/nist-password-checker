A service to give a :+1:/:-1: to a password per [NIST 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5)

## The API

If the API understood your request, it will always return a 200. Look to the `acceptable` value in the response to know
if this password passes muster or not.

### Success

```json
{
  "acceptable": true
}
```

### Failure

When the password is not acceptable, you will get an `acceptable=false` and also a `reason`.

> If the chosen secret is found in the list, the CSP or verifier SHALL advise the subscriber that they need to select a different secret, SHALL provide the reason for rejection, and SHALL require the subscriber to choose a different value.

#### You're in HIBP

```json
{
   "acceptable": false,
   "reason": "appears in a list of compromised passwords 27 times"
}
```

#### GoodPassword1234

```json
{
   "acceptable": false,
   "reason": "Contains repetitive or sequential characters (e.g. ‘aaaaaa’, ‘1234abcd’)"
}
```

## Use with your own copy of the Pwned Passwords database

This service can always reach out to the Pwned Passwords API, or it can use a local copy of the DB read from disk

1. Get the https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader
2. Store the hashes to `hibp/pwnedpasswords`
    ```shell
   haveibeenpwned-downloader.exe hibp/pwnedpasswords -s false
    ```
3. TODO: tell config to use local instead of making API calls