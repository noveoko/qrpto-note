#!/usr/bin/env bash
set -euo pipefail

# ── Rename all "Secure Vault" / "secure-vault" references to Qrpto:note / qrptonote ──
# Run from the repo root: bash rename_to_qrptonote.sh

echo "==> Renaming in src/main.rs"
sed -i 's|Usage: secure-vault|Usage: qrptonote|g' src/main.rs
sed -i 's|Secure Vault  v0.2|Qrpto:note  v0.2|g' src/main.rs

echo "==> Renaming in src/ui.rs"
sed -i 's|Secure Vault  │|Qrpto:note  │|g' src/ui.rs
sed -i 's|🔐  Secure Vault|🔐  Qrpto:note|g' src/ui.rs

echo "==> Renaming in src/storage.rs"
sed -i 's|(Secure Vault, format version 1)|(Qrpto:note vault, format version 1)|g' src/storage.rs
sed -i 's|Not a Secure Vault file|Not a Qrpto:note vault file|g' src/storage.rs

echo "==> Renaming in README.md"
sed -i 's|./target/release/secure-vault|./target/release/qrptonote|g' README.md
sed -i 's|\./secure-vault|./qrptonote|g' README.md

echo "==> Renaming in index.html"
sed -i 's|./target/release/secure-vault|./target/release/qrptonote|g' index.html
sed -i 's|\./secure-vault|./qrptonote|g' index.html

echo ""
echo "==> Verifying no remaining references..."
if grep -rn --include="*.rs" --include="*.md" --include="*.html" --include="*.toml" -i "secure.vault\|secure-vault" .; then
    echo "WARNING: Some references remain (see above)"
else
    echo "All clean. No remaining 'secure-vault' or 'Secure Vault' references."
fi

echo ""
echo "Done. Review with: git diff"
echo "Then commit:       git commit -am 'chore: rename Secure Vault to Qrpto:note'"
