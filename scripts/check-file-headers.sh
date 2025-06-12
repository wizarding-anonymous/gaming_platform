# File: scripts/check-file-headers.sh
#!/usr/bin/env bash

set -euo pipefail

fail=0
while IFS= read -r file; do
    first_line=$(sed -n '1p' "$file" 2>/dev/null || true)
    if [[ "$first_line" == "#!"* ]]; then
        second_line=$(sed -n '2p' "$file" 2>/dev/null || true)
        header_line="$second_line"
    else
        header_line="$first_line"
    fi
    if [[ "$header_line" != *"File: $file"* ]]; then
        echo "Missing or incorrect header in $file"
        fail=1
    fi
done < <(git ls-files)

if [ "$fail" -ne 0 ]; then
    echo "File header check failed"
    exit 1
fi

echo "All file headers are correct"

