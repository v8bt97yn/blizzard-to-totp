The app is a simple GUI that uses blizzards API to quickly convert your SSO Token into a TOTP. 

SSO -> Bearer token -> new authenticator -> secret (hex) -> secret (base64) -> TOTP

---

note: I used "auto-py-to-exe" to convert the python script to exe for anybody who prefers it. idk if it works but its there.

---

1.  Log in to Battlenet and remove any existing Authenticator on your account
3.  Navigate to [account.battle.net/login/en/?ref=localhost](https://account.battle.net/login/en/?ref=localhost)
4.  Copy your SSO Token from the pages URL (ex: US-a3c213213213b213b213b213b213c-123123123)
5.  Paste your SSO token into the app and press run
6.  Copy the TOTP output and use it wherever you want
