# Security policy

## Reporting a vulnerability in PhoneSentry

Please report vulnerabilities privately through GitHub: **Security › Report a vulnerability** on this repository. Don't open a public issue. You should get an answer within 7 days.

## If you think your phone is infected

PhoneSentry is a screening tool. A clean result lowers the likelihood of known threats but can't prove a phone is clean. If you believe you are being targeted by mercenary spyware, get expert help. These organisations help for free:

- Amnesty International Security Lab: https://securitylab.amnesty.org/get-help/
- Access Now Digital Security Helpline: https://www.accessnow.org/help/
- If you suspect stalkerware: https://stopstalkerware.org/

## Verifying downloads

Every release publishes a `PhoneSentry.exe.sha256` file. Check your download with PowerShell:

```powershell
Get-FileHash .\PhoneSentry.exe -Algorithm SHA256
```
