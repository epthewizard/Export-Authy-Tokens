#!/usr/bin/env python3
"""
Authy Exporter

Export and decrypt your Authy TOTP tokens and import them into Bitwarden,
Google Authenticator, Microsoft Authenticator, LastPass, or other TOTP managers.

This script supports multiple export formats (bitwarden, google, microsoft,
lastpass, generic, text) and is the canonical CLI entrypoint for this
repository.
"""

import json
import base64
import argparse
import sys
import csv
from getpass import getpass
from pathlib import Path
from urllib.parse import quote
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def decrypt_token(kdf_rounds, encrypted_seed_b64, salt, passphrase):
    """
    Decrypt a single TOTP token using PBKDF2 and AES-CBC
    """
    try:
        encrypted_seed = base64.b64decode(encrypted_seed_b64)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,
            salt=salt.encode(),
            iterations=kdf_rounds,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())
        
        # Use zero IV as per Authy's implementation
        iv = bytes([0] * 16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_seed) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_len = decrypted_data[-1]
        padding_start = len(decrypted_data) - padding_len
        
        if padding_len > 16 or padding_start < 0:
            raise ValueError("Invalid padding length")
        if not all(pad == padding_len for pad in decrypted_data[padding_start:]):
            raise ValueError("Invalid padding bytes")
        
        decrypted_seed_bytes = decrypted_data[:padding_start]
        
        # Try to decode as ASCII first, fall back to base32
        try:
            return decrypted_seed_bytes.decode('ascii')
        except UnicodeDecodeError:
            return base64.b32encode(decrypted_seed_bytes).decode('ascii').rstrip('=')
        
    except Exception as e:
        return f"ERROR: {str(e)}"


def generate_totp_url(name, issuer, seed, digits=6):
    label = f"{issuer}:{name}" if issuer else name
    url = f"otpauth://totp/{quote(label)}?secret={seed}&digits={digits}"
    if issuer:
        url += f"&issuer={quote(issuer)}"
    return url


def export_bitwarden(tokens_data, output_file):
    bitwarden_items = []
    for token in tokens_data:
        item = {
            "type": 1,
            "name": token["name"],
            "login": {
                "username": token.get("issuer") or "",
                "totp": token["decrypted_seed"]
            },
            "notes": f"Imported from Authy - ID: {token.get('unique_id', 'N/A')}"
        }
        bitwarden_items.append(item)
    output_data = {"encrypted": False, "items": bitwarden_items}
    with open(output_file, "w") as f:
        json.dump(output_data, f, indent=2)
    return output_file


def export_google_authenticator(tokens_data, output_file):
    export_data = {"format": "google-authenticator-export", "tokens": []}
    for token in tokens_data:
        url = generate_totp_url(token["name"], token.get("issuer"), token["decrypted_seed"], token.get("digits", 6))
        export_data["tokens"].append({
            "name": token["name"],
            "issuer": token.get("issuer"),
            "seed": token["decrypted_seed"],
            "digits": token.get("digits", 6),
            "otpauth_url": url
        })
    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)
    return output_file


def export_microsoft_authenticator(tokens_data, output_file):
    export_data = {"format": "microsoft-authenticator-export", "tokens": []}
    for token in tokens_data:
        url = generate_totp_url(token["name"], token.get("issuer"), token["decrypted_seed"], token.get("digits", 6))
        export_data["tokens"].append({
            "name": token["name"],
            "issuer": token.get("issuer"),
            "secret": token["decrypted_seed"],
            "digits": token.get("digits", 6),
            "otpauth_url": url
        })
    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)
    return output_file


def export_lastpass(tokens_data, output_file):
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "issuer", "secret", "digits"])
        for token in tokens_data:
            writer.writerow([token["name"], token.get("issuer") or "", token["decrypted_seed"], token.get("digits", 6)])
    return output_file


def export_generic_json(tokens_data, output_file):
    export_data = {"format": "generic-totp-export", "export_count": len(tokens_data), "tokens": []}
    for token in tokens_data:
        url = generate_totp_url(token["name"], token.get("issuer"), token["decrypted_seed"], token.get("digits", 6))
        export_data["tokens"].append({
            "name": token["name"],
            "issuer": token.get("issuer"),
            "secret": token["decrypted_seed"],
            "digits": token.get("digits", 6),
            "account_type": token.get("account_type"),
            "original_name": token.get("original_name"),
            "unique_id": token.get("unique_id"),
            "otpauth_url": url
        })
    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)
    return output_file


def export_plain_text(tokens_data, output_file):
    with open(output_file, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("TOTP EXPORT - Plain Text Format\n")
        f.write("=" * 80 + "\n\n")
        for i, token in enumerate(tokens_data, 1):
            url = generate_totp_url(token["name"], token.get("issuer"), token["decrypted_seed"], token.get("digits", 6))
            f.write(f"{i}. {token['name']}\n")
            f.write(f"   Issuer:       {token.get('issuer') or 'N/A'}\n")
            f.write(f"   Secret:       {token['decrypted_seed']}\n")
            f.write(f"   Digits:       {token.get('digits', 6)}\n")
            f.write(f"   OTPAuth URL:  {url}\n")
            f.write("\n")
        f.write("=" * 80 + "\n")
        f.write("USAGE INSTRUCTIONS:\n")
        f.write("=" * 80 + "\n")
        f.write("• Use the OTPAuth URLs with QR code generators or manual entry\n")
        f.write("• Most authenticator apps support both methods\n")
        f.write("• Keep this file secure - it contains sensitive authentication data\n")
        f.write("=" * 80 + "\n")
    return output_file


# Export format registry
EXPORT_FORMATS = {
    "bitwarden": {"func": export_bitwarden, "ext": ".json", "desc": "Bitwarden password manager (JSON format)"},
    "google": {"func": export_google_authenticator, "ext": ".json", "desc": "Google Authenticator and compatible apps"},
    "microsoft": {"func": export_microsoft_authenticator, "ext": ".json", "desc": "Microsoft Authenticator"},
    "lastpass": {"func": export_lastpass, "ext": ".csv", "desc": "LastPass Authenticator"},
    "generic": {"func": export_generic_json, "ext": ".json", "desc": "Generic JSON format (compatible with most apps)"},
    "text": {"func": export_plain_text, "ext": ".txt", "desc": "Plain text format (for reference/backup)"}
}


def process_authenticator_data(input_file, backup_password, export_format="bitwarden"):
    try:
        if not Path(input_file).exists():
            print(f"ERROR: Could not find '{input_file}'")
            print("Make sure you've saved the API response JSON to this file.")
            sys.exit(1)
        try:
            with open(input_file, "r") as json_file:
                data = json.load(json_file)
        except json.JSONDecodeError:
            print(f"ERROR: '{input_file}' is not valid JSON")
            print("Check that you copied the API response correctly.")
            sys.exit(1)
        if "authenticator_tokens" not in data:
            print("ERROR: 'authenticator_tokens' key not found in JSON")
            print("Make sure you have the correct API response file.")
            sys.exit(1)
        if not isinstance(data['authenticator_tokens'], list) or len(data['authenticator_tokens']) == 0:
            print("ERROR: No authenticator tokens found in the JSON file")
            print("The 'authenticator_tokens' must be a non-empty list.")
            sys.exit(1)
        decrypted_tokens = []
        failed_tokens = []
        print(f"\nDecrypting {len(data['authenticator_tokens'])} token(s)...\n")
        for idx, token in enumerate(data['authenticator_tokens'], 1):
            try:
                required_fields = ['key_derivation_iterations', 'encrypted_seed', 'salt', 'name']
                missing_fields = [f for f in required_fields if f not in token]
                if missing_fields:
                    print(f"⚠️  Token #{idx} missing fields: {', '.join(missing_fields)}")
                    failed_tokens.append({"name": token.get("name", f"Token #{idx}"), "error": f"Missing fields: {', '.join(missing_fields)}"})
                    continue
                decrypted_seed = decrypt_token(kdf_rounds=token['key_derivation_iterations'], encrypted_seed_b64=token['encrypted_seed'], salt=token['salt'], passphrase=backup_password)
                if decrypted_seed.startswith("ERROR:"):
                    failed_tokens.append({"name": token.get("name", f"Token #{idx}"), "error": decrypted_seed})
                    print(f"❌ {token.get('name', f'Token #{idx}')}: {decrypted_seed}")
                    continue
                token_info = {"name": token.get("name", "Unknown"), "issuer": token.get("issuer"), "decrypted_seed": decrypted_seed, "digits": token.get("digits", 6), "account_type": token.get("account_type"), "original_name": token.get("original_name"), "unique_id": token.get("unique_id")}
                decrypted_tokens.append(token_info)
                print(f"✓ {token.get('name', f'Token #{idx}')}")
            except Exception as e:
                failed_tokens.append({"name": token.get("name", f"Token #{idx}"), "error": str(e)})
                print(f"❌ {token.get('name', f'Token #{idx}')}: {str(e)}")
        if not decrypted_tokens:
            print("\n" + "="*70)
            print("ERROR: No tokens were successfully decrypted")
            print("="*70)
            if failed_tokens:
                print("\nFailed tokens:")
                for failed in failed_tokens:
                    print(f"  - {failed['name']}: {failed['error']}")
            print("\nPossible causes:")
            print("  • Incorrect backup password")
            print("  • Corrupted JSON file")
            print("  • Invalid token data")
            sys.exit(1)
        if export_format not in EXPORT_FORMATS:
            print(f"\nERROR: Unknown export format '{export_format}'")
            print(f"Available formats: {', '.join(EXPORT_FORMATS.keys())}")
            sys.exit(1)
        base_name = Path(input_file).stem
        ext = EXPORT_FORMATS[export_format]["ext"]
        output_file = f"{base_name}_export_{export_format}{ext}"
        try:
            export_func = EXPORT_FORMATS[export_format]["func"]
            output_file = export_func(decrypted_tokens, output_file)
        except Exception as e:
            print(f"\nERROR: Failed to export in {export_format} format: {str(e)}")
            sys.exit(1)
        return output_file, decrypted_tokens, failed_tokens
    except Exception as e:
        print(f"ERROR: Unexpected error during processing: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def print_success_summary(output_file, decrypted_tokens, failed_tokens, export_format):
    print("\n" + "="*80)
    print("✓ DECRYPTION COMPLETED SUCCESSFULLY")
    print("="*80)
    print(f"\n✓ Decrypted {len(decrypted_tokens)} authenticator token(s)")
    if failed_tokens:
        print(f"⚠️  {len(failed_tokens)} token(s) failed to decrypt")
    print(f"✓ Export file saved to: '{output_file}'")
    print(f"✓ Export format: {EXPORT_FORMATS[export_format]['desc']}")
    print("\n" + "-"*80)
    print("DECRYPTED TOKENS DETAILS:")
    print("-"*80)
    for i, token in enumerate(decrypted_tokens, 1):
        url = generate_totp_url(token["name"], token.get("issuer"), token["decrypted_seed"], token.get("digits", 6))
        print(f"\n{i}. {token['name']}")
        print(f"   Issuer:       {token.get('issuer') or 'N/A'}")
        print(f"   Account Type: {token.get('account_type') or 'N/A'}")
        print(f"   Secret:       {token.get('decrypted_seed')}")
        print(f"   Digits:       {token.get('digits', 6)}")
        print(f"   OTPAuth URL:  {url}")
    if failed_tokens:
        print("\n" + "-"*80)
        print("FAILED TOKENS:")
        print("-"*80)
        for failed in failed_tokens:
            print(f"✗ {failed['name']}: {failed['error']}")
    print("\n" + "-"*80)
    print("IMPORT OPTIONS:")
    print("-"*80)
    if export_format == "bitwarden":
        print("\n1. Bitwarden Web Vault (Recommended):")
        print("   • Go to https://vault.bitwarden.com/")
        print("   • Login to your account")
        print("   • Settings → Tools → Import Data")
        print(f"   • Select 'Bitwarden (json)' format")
        print(f"   • Upload '{output_file}'")
        print("   • Click 'Import Data'")
    elif export_format == "google":
        print("\n1. Google Authenticator:")
        print("   • Open Google Authenticator on your phone")
        print("   • Use the OTPAuth URLs above or scan generated QR codes")
        print("   • Tap the '+' button → Enter setup key")
        print("   • Enter the 'Secret' value and service name")
    elif export_format == "microsoft":
        print("\n1. Microsoft Authenticator:")
        print("   • Open Microsoft Authenticator on your phone")
        print("   • Tap '+' → Other account")
        print("   • Use the OTPAuth URLs or scan QR codes")
    elif export_format == "lastpass":
        print("\n1. LastPass Authenticator:")
        print("   • Open LastPass Authenticator")
        print("   • The CSV file can be imported or manually entered")
    else:
        print("\n1. Manual Entry:")
        print("   • Use the 'Secret' values above")
        print("   • Use the 'OTPAuth URL' for QR code generation")
        print("   • Scan the QR code or enter the secret manually")
    print("\n2. QR Code Generation:")
    print("   • Use any online QR code generator")
    print("   • Paste the 'OTPAuth URL' from above")
    print("   • Scan the generated QR code in your authenticator app")
    print("\n" + "="*80)
    print("SECURITY REMINDERS:")
    print("="*80)
    print("⚠️  DELETE FILES AFTER IMPORT:")
    print("   • Delete 'authenticator_tokens.json' (contains encrypted data)")
    print(f"   • Delete '{output_file}' (contains decrypted secrets) or secure backup")
    print("\n⚠️  REMOVE PROXY FROM iOS:")
    print("   • Settings → Wi-Fi → (i) → HTTP Proxy → Off")
    print("\n⚠️  UNINSTALL mitmproxy CERTIFICATE:")
    print("   • Settings → General → VPN & Device Management → mitmproxy → Delete")
    print("   • Settings → General → About → Certificate Trust Settings → Disable mitmproxy")
    print("\n✓ Disable proxy on computer:")
    print("   • Stop the mitmweb terminal (Ctrl+C)")
    print("   • Optional: pip uninstall mitmproxy")
    print("="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Decrypt Authy TOTP tokens and export to various formats", formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Examples:
  # Export to Bitwarden (default)
  python authy_exporter.py

  # Export to Google Authenticator
  python authy_exporter.py --format google

  # Export to LastPass
  python authy_exporter.py --format lastpass

  # Use custom input file
  python authy_exporter.py -i my_tokens.json -f generic

Available formats:
  bitwarden - Bitwarden password manager (recommended)
  google    - Google Authenticator
  microsoft - Microsoft Authenticator
  lastpass  - LastPass Authenticator
  generic   - Generic JSON (compatible with most apps)
  text      - Plain text with OTPAuth URLs
        """)
    parser.add_argument("-i", "--input", default="authenticator_tokens.json", help="Input JSON file with encrypted tokens (default: authenticator_tokens.json)")
    parser.add_argument("-f", "--format", choices=list(EXPORT_FORMATS.keys()), default="bitwarden", help="Export format (default: bitwarden)")
    parser.add_argument("-l", "--list-formats", action="store_true", help="List all available export formats and exit")
    args = parser.parse_args()
    if args.list_formats:
        print("\nAvailable Export Formats:\n")
        for fmt, info in EXPORT_FORMATS.items():
            print(f"  {fmt:<10} - {info['desc']}")
        print()
        sys.exit(0)
    backup_password = getpass("Enter your Authy backup password: ").strip()
    if not backup_password:
        print("ERROR: Backup password cannot be empty")
        sys.exit(1)
    output_file, decrypted_tokens, failed_tokens = process_authenticator_data(args.input, backup_password, args.format)
    print_success_summary(output_file, decrypted_tokens, failed_tokens, args.format)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
