# Export Authy to Bitwarden and Other Authenticators 

🔐 Simple, local-only Authy TOTP exporter and converter.

A no-fluff, single-file workflow to export and decrypt your Authy TOTP tokens locally. Capture the Authy API response with `mitmweb`, save the JSON, then run `authy_exporter.py` and enter your Authy backup password to produce OTPAuth URLs and Bitwarden-compatible exports. Everything you need is in this README; the old `docs/` folder has been retired.

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)

## Quick Links

- Step-by-step guide (this section)
- Troubleshooting anchors (bottom of file)
- Script usage (`python authy_exporter.py --help`)

## Step-by-Step Guide (single canonical flow)

Follow these steps in order — this is the single, canonical guide. Troubleshooting and edge-case fixes are linked in the Troubleshooting section below. This README is the only detailed, newbie-friendly guide you need; the `docs/` folder has been retired so you can stay in one file.

### 1) Install Python, mitmproxy, and dependencies

**Windows (PowerShell)**
1. Download Python from https://www.python.org/downloads/ and run the installer. During setup, **check Add Python to PATH** and choose **Install Now**; alternatively install via winget:

```powershell
winget install --id Python.Python.3 -e --source winget
```

2. Open a new PowerShell window and confirm Python and pip are available:

```powershell
python --version
pip --version
```

If these commands show "not found" or "command is not recognized," [click here](#windows-path) for Windows PATH & PowerShell troubleshooting.

3. Create and activate a virtual environment:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

If PowerShell refuses to run `Activate.ps1`, [click here](#windows-path) for the execution policy fix.

4. Upgrade pip and install the Python packages you need:

```powershell
python -m pip install --upgrade pip
pip install cryptography mitmproxy
```

If `pip install` fails, [click here](#install-troubleshooting) for install fixes on Windows/macOS/Linux.

**macOS (Homebrew)**
1. Install Homebrew if you do not already have it: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`.
2. Use Homebrew to install Python and mitmproxy:

```bash
brew update
brew install python
brew install mitmproxy
```

3. Create+activate a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install cryptography mitmproxy
```

If any install step breaks, [click here](#install-troubleshooting).

**Linux (Debian / Ubuntu)**
1. Install Python and helper packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

2. Create and activate a virtualenv, then install pip dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install cryptography mitmproxy
```

If anything fails (SSL errors, missing packages), [click here](#install-troubleshooting).

### 2) Create your Authy backup password (required)
1. Open Authy on your phone → **Settings → Accounts** → **Create Backup Password**.
2. Set a strong password and write it down temporarily; you will enter it when the script runs in step 6.

### 3) Start mitmweb, install the iOS certificate, and configure the proxy
1. Run mitmweb from the activated virtualenv or system shell:

```bash
mitmweb
```

2. Keep the terminal open; note the web interface at `http://127.0.0.1:8081` and that the proxy listens on port `8080`.
3. On your iPhone Wi-Fi settings, set **HTTP Proxy** to **Manual** and enter your computer's IPv4 address (find it with `ipconfig` or `ip addr show`) plus port `8080`.
4. On the phone, open Safari and visit `http://mitm.it`, install the mitmproxy profile, then trust it via **Settings → General → About → Certificate Trust Settings**.

If the proxy does not load traffic, [click here](#mitmproxy-troubleshooting). If certificate installation fails or HTTPS requests give security warnings, [click here](#ios-certs).

### 4) Capture the Authy API request
1. In the mitmweb interface, type in the search bar:

```
~d "api.authy.com" token
```

2. In Authy on the phone, go to **Settings → Accounts**, toggle **Backup** to **OFF**, and when prompted, tap **Don't Disable** (this triggers the API request without deleting your backup password).
3. Switch back to mitmweb, find the GET request to `api.authy.com`, and open it. The request URL will look like `https://api.authy.com/json/users/...&apps=123,...`
4. Copy the full URL, paste it into a text editor, and delete everything after `apps=` (leave the trailing `apps=`). You must trim it before pasting it into your browser or curl.

  **Example request you should see in mitmweb**:

  ```txt
  https://api.authy.com/json/users/63351862/authenticator_tokens?locale=en&api_key={api_key_here}&otp2={otp_2_here}&otp3={otp_3_here}&device_id={device_id_here}&apps={list_of_app_ids}
  ```

  When trimmed, the URL should end with `apps=` (no app IDs). Paste that trimmed URL into your browser.

If the trimmed URL returns HTML or redirects, [click here](#saving-json) for alternate download commands.

### 5) Save the encrypted tokens JSON
1. Paste the trimmed URL into your computer browser and press Enter.
2. From the response page, choose **View Source / Raw Data**, copy the entire JSON payload, and save it as `authenticator_tokens.json` in the same folder as `authy_exporter.py`.
3. After saving, make sure the JSON starts like this example (each field should be present for each token):

```json
{
  "message": "success",
  "authenticator_tokens": [
    {
      "account_type": "{name of account}",
      "digits": "{digits}",
      "encrypted_seed": "{seed_here}",
      "issuer": "{issuer}",
      "key_derivation_iterations": "{iterations}",
      "logo": "{logo}",
      "name": "{name}",
      "original_name": "{original_name_here}",
      "password_timestamp": "{pw_timestamp}",
      "salt": "{salt_here}",
      "unique_id": "{uid_here}",
      "unique_iv": "{uiv_here}"
    }
  ]
}
```
3. Double-check the file contains the `authenticator_tokens` array and `encrypted_seed` fields for each entry.

If browsers still show HTML or you prefer a CLI download, [click here](#saving-json) for `curl`/`wget` commands.

### 6) Decrypt and convert your tokens
1. Run the exporter script (it will prompt for the Authy backup password created in Step 2):

```bash
python authy_exporter.py
```

2. Enter the backup password when prompted. The script decrypts the tokens and writes an export file such as `authenticator_tokens_export_bitwarden.json`, and prints `otpauth://` URLs you can copy.

If you see `Decryption failed` or invalid data, [click here](#decryption-troubleshooting) for checks.
See example commands for running the script in the "Script examples for noobs" section: [click here](#script-examples).

### 7) Import the data into Bitwarden or another TOTP manager, then clean up
1. For Bitwarden bulk import: log into https://vault.bitwarden.com → **Settings → Tools → Import Data**, select **Bitwarden (json)**, and upload the exported JSON file.
2. Alternatively, open the export, copy the `decrypted_seed` for a specific account, and paste it into that login item under **Authenticator Key (TOTP)**.
3. After importing, delete `authenticator_tokens.json`, the export file, stop `mitmweb` (`Ctrl+C`), and remove the HTTP proxy configuration from your iPhone Wi-Fi settings.
4. Uninstall the mitmproxy profile: Settings → General → VPN & Device Management → mitmproxy → Delete Profile, then disable the trust toggle under Certificate Trust Settings.

If Bitwarden rejects the JSON or shows errors, [click here](#bitwarden-import); for cleanup reminders revisit the Security Notes below.

<a name="script-examples"></a>
## Script examples for noobs

Use these copy-and-paste commands once you have `authenticator_tokens.json` and your backup password ready:

- **List every supported export format**

  ```bash
  python authy_exporter.py --list-formats
  ```

- **Export to Bitwarden (default)**

  ```bash
  python authy_exporter.py
  ```

- **Export to Google Authenticator format**

  ```bash
  python authy_exporter.py --format google
  ```

- **Export to LastPass CSV with a custom JSON input file**

  ```bash
  python authy_exporter.py -i my_tokens.json -f lastpass
  ```

- **Get plain-text output with OTPAuth URLs (good for manual copy/paste)**

  ```bash
  python authy_exporter.py --format text
  ```

Each command prompts you for the Authy backup password (you set it in Step 2). After the script finishes, you can find the exported file next to `authenticator_tokens.json` — the file name follows the pattern `<input>_export_<format>.<ext>`.
## Troubleshooting

Advanced troubleshooting and a collection of fixes for path/cert/proxy issues are available in this community gist:

- https://gist.github.com/gboudreau/94bb0c11a6209c82418d01a59d958c93

If the quick fixes below don't resolve your issue, check the gist for additional steps and user-contributed solutions.

### mitmweb shows "Certificate Verification Error"

**Problem**: iOS doesn't trust the mitmproxy certificate.

**Solution**:
1. Go to **Settings → General → About → Certificate Trust Settings**
2. Make sure the mitmproxy toggle is **enabled**

### No requests appear in mitmweb

**Problem**: Proxy isn't configured correctly.

**Solution**:
1. Verify your iPhone proxy settings match your computer's IP and port 8080
2. Make sure mitmweb is still running
3. Try visiting `http://example.com` in Safari - you should see it in mitmweb

### "Decryption failed" errors

**Problem**: Wrong backup password or corrupted data.

**Solution**:
1. Verify you're using the correct backup password from Authy
2. Try exporting the tokens again from the API
3. Make sure the JSON file is valid (check for syntax errors)

### API request doesn't appear

**Problem**: Authy changed their flow or you didn't trigger the request correctly.

**Solution**:
1. Make sure you set the filter in mitmweb: `~d "api.authy.com" token`
2. Try toggling the backup switch **off** then immediately tap "Don't Disable"
3. Look for any request to `api.authy.com` in mitmweb (even without the filter)

### Import fails in Bitwarden

**Problem**: JSON format is incorrect.

**Solution**:
1. Open `bitwarden_import.json` and verify it's valid JSON
2. Make sure it has the structure:
   ```json
   {
     "encrypted": false,
     "items": [...]
   }
   ```
3. Try importing just one item first to test

---

## Security Notes

🔒 **Important Security Considerations**:

- ⚠️ **Delete sensitive files after import**: `authenticator_tokens.json`, `bitwarden_import.json`
- ⚠️ **Remove the proxy from your iPhone** after you're done:
  - Settings → Wi-Fi → (i) → HTTP Proxy → **Off**
- ⚠️ **Uninstall the mitmproxy certificate** from your iPhone:
  - Settings → General → VPN & Device Management → mitmproxy → Delete Profile
  - Settings → General → About → Certificate Trust Settings → Disable mitmproxy
- ⚠️ **Never share** your API keys, device IDs, or OTP codes
- ⚠️ **Never commit** these files to git (the `.gitignore` protects you)
- ✅ **Use a strong master password** in Bitwarden to protect your TOTP codes

---

## Clean Up

---

<a name="windows-path"></a>
## Windows PATH & PowerShell Troubleshooting

If Windows reports `python` or `pip` as not found, or PowerShell refuses to run `Activate.ps1`, follow these steps.

1) Verify Python is installed via the python launcher `py`:

```powershell
py -3 --version
```

If `py` returns a version, use `py -3 -m venv venv` and `venv\Scripts\Activate.ps1` instead of `python`.

2) Add Python to PATH (if you used the installer and forgot to check "Add Python to PATH"):

- Re-run the installer and choose "Modify" → check "Add Python to PATH" → Continue, or
- Manually add the Python installation directory (e.g., `C:\Users\<you>\AppData\Local\Programs\Python\Python39\`) and the Scripts folder to your PATH via System → Advanced → Environment Variables → Edit `Path`.

Then open a NEW PowerShell window and run:

```powershell
python --version
pip --version
```

3) PowerShell execution policy prevents scripts from running (common when activating venv):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

This allows local scripts (like `Activate.ps1`) to run for your user. To revert later:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser
```

4) If `py`/`python` still aren't working, use the full path to the executable as a workaround, for example:

```powershell
C:\Users\yourname\AppData\Local\Programs\Python\Python39\python.exe -m venv venv
```

---

<a name="mitmproxy-troubleshooting"></a>
## mitmweb & Proxy Troubleshooting

If `mitmweb` is running but you don't see requests from your phone, try these steps **in order**:

1) Confirm `mitmweb` is running and showing the web UI at `http://127.0.0.1:8081` on your computer.

```bash
mitmweb
```

2) Verify your phone's Wi‑Fi HTTP Proxy is set to your computer's IP and port `8080` (Manual). See the Step‑by‑Step section for how to find your IPv4 address.

3) Ensure your computer and phone are on the same Wi‑Fi network. Disable VPNs on the phone and the computer while capturing.

4) Check firewall rules on your computer — temporarily allow `mitmproxy`/`python` or the listening port `8080`.

5) Visit `http://mitm.it` on the phone and re-install the mitmproxy profile; then re-enable the Certificate Trust toggle under Settings → General → About → Certificate Trust Settings.

6) If the request still does not appear, open mitmweb logs (the terminal running mitmweb) and look for errors or dropped connections.

7) Common gotcha: when copying the request URL from mitmweb, make sure you copy the full request URL (including `apps=`) and then trim everything AFTER `apps=` (leave `apps=` but remove app ids). If you paste a malformed URL into the browser, it may redirect or return HTML instead of raw JSON.

8) External docs: if these steps don't help, the official mitmproxy docs have extra details on certs, proxying, and troubleshooting: https://docs.mitmproxy.org/stable/

---

<a name="install-troubleshooting"></a>
## Install Troubleshooting (macOS / Linux / pip issues)

If `pip install` or platform package installs fail, try these step‑by‑step fixes depending on your OS.

macOS (Homebrew):

```bash
brew update
brew install python
brew install mitmproxy
```

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

If `pip install mitmproxy` fails with build or SSL errors, upgrade pip and install wheel first:

```bash
python -m pip install --upgrade pip setuptools wheel
pip install mitmproxy
```

If you encounter SSL certificate errors while installing packages on macOS, run the `Install Certificates.command` that ships with the Python installer (path may vary):

```bash
/Applications/Python\ 3.x/Install\ Certificates.command
```

---

<a name="saving-json"></a>
## Saving / Viewing Raw JSON Troubleshooting

If your browser shows HTML or redirects instead of raw JSON, try one of these alternatives:

1) Use `curl` to fetch the trimmed URL directly (replace the URL you copied):

```bash
curl -L "<paste-the-trimmed-url-here>" -o authenticator_tokens.json
```

2) Use `wget`:

```bash
wget -O authenticator_tokens.json "<paste-the-trimmed-url-here>"
```

3) If you see a login page or redirect, confirm you trimmed the URL so it ends with `apps=` (remove app ids). A malformed URL can return HTML instead of JSON.

---

<a name="decryption-troubleshooting"></a>
## Decryption Troubleshooting

If `authy_exporter.py` reports `Decryption failed` or produces invalid seeds, follow these checks in order:

1) Confirm you created the Authy backup password in Step 1 and that you type it exactly (no leading/trailing spaces).
2) Ensure `authenticator_tokens.json` contains the `authenticator_tokens` array and valid fields; validate with `jq` or https://jsonlint.com/.
3) Try decrypting a single token with the script using `-i` to point at a minimal JSON containing just one token to isolate failures.
4) If you see KDF iteration mismatches or base64 errors, re-export the JSON using `curl`/`wget` (see "Saving / Viewing Raw JSON Troubleshooting") and retry.

If these steps don't help, consult the troubleshooting gist linked above or open an issue with the exact error output and a sanitized sample of the token JSON.

---

<a name="bitwarden-import"></a>
## Bitwarden Import Troubleshooting

If Bitwarden refuses to import the JSON file:

1) Validate the JSON structure at https://jsonlint.com/.
2) Ensure the top-level structure matches Bitwarden's expected format: `{"encrypted": false, "items": [ ... ]}`.
3) If Bitwarden complains about missing fields, open the JSON and inspect one item to confirm `name` and `login`/`notes` are present.
4) As a test, create a minimal JSON file with a single item and try importing that to find the problematic item.

---

<a name="ios-certs"></a>
## iOS Certificate & Profile Troubleshooting

If `http://mitm.it` appears to install the profile but you still see certificate errors or no HTTPS traffic:

1) Delete any existing mitmproxy profile on the iPhone: Settings → General → VPN & Device Management → mitmproxy → Delete Profile.
2) Reboot the iPhone.
3) Re-open Safari and go to `http://mitm.it` to reinstall the profile; then enable trust under Settings → General → About → Certificate Trust Settings.
4) Ensure the phone's date/time are correct and that no MDM policy blocks profile installation.


## Other Common Issues

- If you get `Decryption failed`, re-check that you created the Authy backup password beforehand and typed it correctly when prompted. See Step 1 above.
- If Bitwarden import fails with a JSON error, open the export in a text editor and validate it via https://jsonlint.com/.


After successfully importing to Bitwarden:

```bash
# Delete sensitive files
rm authenticator_tokens.json
rm bitwarden_import.json

# Stop mitmweb (Ctrl+C in the terminal)

# Remove proxy from iPhone (see Security Notes above)

# Optional: Uninstall mitmproxy
pip uninstall mitmproxy
```

---

## File Structure

```
authy-to-bitwarden/
├── authy_exporter.py           # Main decryption script (canonical entrypoint)
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── LICENSE                     # MIT License
├── .gitignore                  # Protects sensitive files
├── authenticator_tokens.json   # Your encrypted tokens (not tracked)
└── authenticator_tokens_export_bitwarden.json  # Decrypted output (not tracked)
```

---

## License

MIT License - see LICENSE file for details.

---

## Disclaimer

This tool is for **personal use only** to migrate your own authenticator tokens. Always keep secure backups of your TOTP codes. The authors are not responsible for any data loss or security issues.

**By using this tool, you acknowledge**:
- You understand the security implications of intercepting HTTPS traffic
- You will properly clean up certificates and proxies after use
- You will securely delete sensitive files after import
- This is only for migrating your own personal data

---

## Credits

- Built with [mitmproxy](https://mitmproxy.org/)
- Uses Python [cryptography](https://cryptography.io/) library

---

## Support

If you encounter issues:
1. Check the [Troubleshooting](#troubleshooting) section
2. Verify all steps were followed correctly
3. Open an issue on GitHub with details about your error

**Happy migrating! 🎉**
