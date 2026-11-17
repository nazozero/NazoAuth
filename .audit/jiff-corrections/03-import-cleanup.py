from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1])
paths = [root / p for p in subprocess.check_output(['git', '-C', str(root), 'ls-files', '*.rs'], text=True).splitlines()]
remaining = []
for path in paths:
    old = path.read_text()
    text = re.sub(r'^\s*use (?:chrono|jiff)::(?:\{\s*\})?;\s*$', '', old, flags=re.M)
    if text != old:
        path.write_text(text)
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(r'chrono|\bUtc\b|\bDateTime\b|try_seconds|\.to_std\(|\.to_rfc3339|\.timestamp\(|SystemTime|\.timestamp_opt\(', line):
            remaining.append(f'{path.relative_to(root)}:{number}: {line.strip()}')
(root / '.verification').mkdir(exist_ok=True)
(root / '.verification/time-remaining.txt').write_text('\n'.join(remaining) + '\n')
