#!/usr/bin/env python3
"""One-time mechanical migration, followed by reviewed semantic corrections.

This script runs only against the isolated validation branch. A successful
transformation is not a validation result; cargo diagnostics and tests follow.
"""
from pathlib import Path
import re
import shutil
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
independent = Path(sys.argv[2]).resolve()
paths = [root / p for p in subprocess.check_output(
    ['git', '-C', str(root), 'ls-files'], text=True).splitlines()]


def closing(text, start):
    depth = 1
    in_string = False
    escaped = False
    for i in range(start + 1, len(text)):
        c = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i
    raise ValueError('unbalanced call near ' + text[max(0, start - 80):start + 80])


def calls(text, pattern, convert):
    matches = list(re.finditer(pattern, text))
    for match in reversed(matches):
        start = match.end() - 1
        end = closing(text, start)
        replacement = convert(match, text[start + 1:end])
        text = text[:match.start()] + replacement + text[end + 1:]
    return text


manifest = root / 'Cargo.toml'
if re.search(r'^chrono\s*=', manifest.read_text(), re.M):
    profile = 'crates/server/tests/unit/domain/passkey/profile.rs'
    shutil.copyfile(independent / profile, root / profile)
    value = manifest.read_text().replace(
        'b3ecfa40c8f626903f36d6065640236ac87fe472',
        '84938674306a2ca0b84319e8ee499b61b8f32e84')
    manifest.write_text(value)
    for path in paths:
        if path.suffix != '.rs':
            continue
        old = path.read_text()
        if 'chrono' not in old:
            continue
        text = old
        had_duration = bool(re.search(r'use chrono::(?:\{[^}]*\bDuration\s*[,}]|Duration\s*;)', text, re.S))
        if str(path.relative_to(root)) == 'crates/authorization-server/src/domain/openid4vc/credential_crypto/mdoc.rs':
            text = re.sub(r'\bTimestamp\b', 'MdocTimestamp', text)
            text = re.sub(r'([,{]\s*)MdocTimestamp(?=\s*[,}])', r'\1Timestamp as MdocTimestamp', text)
        def import_items(match):
            items = []
            for item in match.group(1).split(','):
                item = item.strip()
                if not item:
                    continue
                if item in ('TimeZone', 'SecondsFormat'):
                    continue
                if item in ('DateTime', 'Utc'):
                    item = 'Timestamp'
                elif item.startswith('Duration'):
                    item = 'SignedDuration'
                elif item == 'NaiveDate':
                    item = 'civil::Date'
                if item not in items:
                    items.append(item)
            if not items:
                return ''
            return 'use jiff::' + (items[0] if len(items) == 1 else '{' + ', '.join(items) + '}') + ';'
        text = re.sub(r'use chrono::\{([^}]+)\};', import_items, text, flags=re.S)
        text = re.sub(r'use chrono::(?:DateTime|Utc);', 'use jiff::Timestamp;', text)
        text = re.sub(r'use chrono::Duration(?: as \w+)?;', 'use jiff::SignedDuration;', text)
        text = re.sub(r'use chrono::(?:TimeZone|SecondsFormat);', '', text)
        text = re.sub(r'chrono::DateTime(?:::)?\s*<\s*(?:chrono::)?Utc\s*>', 'jiff::Timestamp', text)
        text = re.sub(r'(?<!:)\bDateTime(?:::)?\s*<\s*(?:chrono::)?Utc\s*>', 'Timestamp', text)
        text = text.replace('chrono::Utc::now', 'jiff::Timestamp::now').replace('Utc::now', 'Timestamp::now')
        text = text.replace('chrono::Duration', 'jiff::SignedDuration')
        text = re.sub(r'\bChronoDuration\b', 'SignedDuration', text)
        if had_duration:
            text = re.sub(r'(?<![:\w])Duration\b', 'SignedDuration', text)
        text = text.replace('chrono::DateTime::', 'jiff::Timestamp::').replace('DateTime::', 'Timestamp::')
        text = text.replace('Timestamp::MAX_UTC', 'Timestamp::MAX')
        text = text.replace('Utc.timestamp_opt(', 'Timestamp::new(')
        text = text.replace('Timestamp::from_timestamp_micros(', 'Timestamp::from_microsecond(')
        text = text.replace('Timestamp::from_timestamp(', 'Timestamp::new(')
        text = calls(text, r'(?:jiff::)?Timestamp::new\(', lambda m, a: m.group(0) + a + ')')
        text = re.sub(r'(Timestamp::new\([^\n;]*?\))\.single\(\)', r'\1', text)
        for old_name, new_name in [('nanoseconds', 'from_nanos'), ('microseconds', 'from_micros'), ('milliseconds', 'from_millis'), ('seconds', 'from_secs'), ('minutes', 'from_mins'), ('hours', 'from_hours')]:
            text = text.replace('SignedDuration::' + old_name + '(', 'SignedDuration::' + new_name + '(')
        text = calls(text, r'((?:jiff::)?SignedDuration)::days\(', lambda m, a: m.group(1) + '::from_hours((' + a + ') * 24)')
        for a, b in [('.num_seconds()', '.as_secs()'), ('.num_milliseconds()', '.as_millis()'), ('.signed_duration_since(', '.duration_since('), ('.checked_add_signed(', '.checked_add('), ('.timestamp_micros()', '.as_microsecond()'), ('.timestamp_millis()', '.as_millisecond()'), ('.timestamp_subsec_nanos()', '.subsec_nanosecond()'), ('.timestamp()', '.as_second()'), ('.to_rfc3339()', '.to_string()')]:
            text = text.replace(a, b)
        text = text.replace('.not_before.as_second()', '.not_before.timestamp()').replace('.not_after.as_second()', '.not_after.timestamp()')
        text = text.replace('.with_timezone(&Utc)', '').replace('.with_timezone(&chrono::Utc)', '')
        text = calls(text, r'(?:jiff::)?Timestamp::parse_from_rfc3339\(', lambda m, a: '(' + a + ').parse::<jiff::Timestamp>()')
        text = re.sub(r'chrono::NaiveDate::parse_from_str\(([^,]+),\s*"%Y-%m-%d"\)', r'(\1).parse::<jiff::civil::Date>()', text)
        if text != old:
            path.write_text(text)

    for path in paths:
        if path.name != 'Cargo.toml':
            continue
        text = path.read_text()
        if path == manifest:
            text = re.sub(r'^chrono\s*=.*$', 'jiff = { version = "0.2.42", default-features = false, features = ["std", "serde", "js"] }\njiff-diesel = { version = "0.1.4", features = ["postgres"] }', text, flags=re.M)
        elif 'workspace' in text:
            text = re.sub(r'^chrono\s*=.*$', 'jiff.workspace = true', text, flags=re.M)
            text = text.replace('chrono.workspace = true', 'jiff.workspace = true')
        else:
            text = re.sub(r'^chrono\s*=.*$', 'jiff = { version = "0.2.42", default-features = false, features = ["std", "serde"] }', text, flags=re.M)
        text = text.replace('"chrono", ', '').replace(', "chrono"', '').replace('"chrono",\n', '')
        path.write_text(text)

    # The official adapter stays at SQL boundaries; domain models retain Jiff.
    timestamp_columns = set()
    for path in paths:
        if path.name == 'schema.rs':
            timestamp_columns.update(re.findall(r'^\s*(\w+)\s*->\s*(?:Nullable<)?Timestamptz', path.read_text(), re.M))
    sql_crates = set()
    for path in paths:
        if path.suffix != '.rs':
            continue
        text = path.read_text()
        if 'diesel' not in text and '/persistence-postgres/' not in str(path):
            continue
        old = text
        def rows(match):
            attrs, declaration, body = match.group(1, 2, 3)
            if 'Queryable' not in attrs:
                return match.group(0)
            def field(m):
                nullable = m.group(3).startswith('Option<')
                wrapper = 'NullableTimestamp' if nullable else 'Timestamp'
                return m.group(1) + '#[diesel(deserialize_as = jiff_diesel::' + wrapper + ')]\n' + m.group(0)
            body = re.sub(r'^(\s*)((?:pub(?:\([^)]*\))?\s+)?\w+:\s*)(Option<(?:jiff::)?Timestamp>|(?:jiff::)?Timestamp)(,)', field, body, flags=re.M)
            return attrs + declaration + body + '}'
        text = re.sub(r'((?:#\[[^\]]*\]\s*)+)((?:pub(?:\([^)]*\))?\s+)?struct\s+\w+[^\{]*\{)([^}]*)(})', rows, text, flags=re.S)
        need_trait = False
        def bind(match, arg):
            nonlocal_placeholder = None
            if 'Timestamptz' not in match.group(1):
                return match.group(0) + arg + ')'
            return match.group(0) + '(' + arg + ').to_diesel())'
        text = calls(text, r'\.bind::<([^()]*?)>\(', bind)
        if timestamp_columns:
            pattern = r'(\b(?:' + '|'.join(sorted(timestamp_columns)) + r')\.(?:eq|ne|lt|le|gt|ge))\('
            def expression(match, arg):
                # Comparisons between two columns remain database expressions.
                if re.fullmatch(r'\s*(?:[\w]+::)+[\w]+\s*', arg) and 'Timestamp::' not in arg:
                    return match.group(0) + arg + ')'
                return match.group(0) + '(' + arg + ').to_diesel())'
            text = calls(text, pattern, expression)
        if '.to_diesel()' in text:
            text += '\nuse jiff_diesel::ToDiesel as _;\n'
        if text != old:
            path.write_text(text)
            relative = path.relative_to(root)
            if relative.parts[0] == 'crates':
                sql_crates.add((relative.parts[1], relative.parts[2] == 'src'))
    for name, production in sql_crates:
        path = root / 'crates' / name / 'Cargo.toml'
        text = path.read_text()
        if 'jiff-diesel' not in text:
            section = '[dependencies]' if production else '[dev-dependencies]'
            if section in text:
                text = text.replace(section, section + '\njiff-diesel.workspace = true', 1)
            else:
                text += '\n' + section + '\njiff-diesel.workspace = true\n'
            path.write_text(text)

print('Candidate changed-file count:', len(subprocess.check_output(
    ['git', '-C', str(root), 'diff', '--name-only'], text=True).splitlines()))
