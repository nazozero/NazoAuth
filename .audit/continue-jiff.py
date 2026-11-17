#!/usr/bin/env python3
"""Stage a native Jiff migration only in the isolated validation checkout.
Compilation and semantic regression tests are separate mandatory gates.
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
    depth, in_string, escaped = 1, False, False
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
    for match in reversed(list(re.finditer(pattern, text))):
        start = match.end() - 1
        end = closing(text, start)
        text = text[:match.start()] + convert(match, text[start + 1:end]) + text[end + 1:]
    return text


manifest = root / 'Cargo.toml'
if re.search(r'^chrono\s*=', manifest.read_text(), re.M):
    profile = 'crates/server/tests/unit/domain/passkey/profile.rs'
    shutil.copyfile(independent / profile, root / profile)
    manifest.write_text(manifest.read_text().replace(
        'b3ecfa40c8f626903f36d6065640236ac87fe472',
        '84938674306a2ca0b84319e8ee499b61b8f32e84'))
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
                if not item or item in ('TimeZone', 'SecondsFormat'):
                    continue
                if item in ('DateTime', 'Utc'):
                    item = 'Timestamp'
                elif item.startswith('Duration'):
                    item = 'SignedDuration'
                elif item == 'NaiveDate':
                    item = 'civil::Date'
                if item not in items:
                    items.append(item)
            return '' if not items else 'use jiff::' + (items[0] if len(items) == 1 else '{' + ', '.join(items) + '}') + ';'
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
        else:
            def dependency(match):
                if 'workspace' in match.group(0):
                    return 'jiff.workspace = true'
                return 'jiff = { version = "0.2.42", default-features = false, features = ["std", "serde"] }'
            text = re.sub(r'^chrono(?:\.workspace)?\s*=.*$', dependency, text, flags=re.M)
        text = text.replace('"chrono", ', '').replace(', "chrono"', '').replace('"chrono",\n', '')
        path.write_text(text)

    timestamp_columns = set()
    for path in paths:
        if path.name == 'schema.rs':
            timestamp_columns.update(re.findall(r'^\s*(\w+)\s*->\s*(?:Nullable<)?Timestamptz', path.read_text(), re.M))
    row_pattern = re.compile(r'(?P<attrs>(?:#\[[^\]]*\]\s*)+)(?P<declaration>(?:pub(?:\([^)]*\))?\s+)?struct\s+\w+[^\{]*\{)(?P<body>[^}]*)}', re.S)
    sql_crates = {}
    for path in paths:
        if path.suffix != '.rs':
            continue
        text = path.read_text()
        if 'diesel' not in text and '/persistence-postgres/' not in str(path):
            continue
        old = text
        def rows(match):
            attrs, declaration, body = (match[name] for name in ('attrs', 'declaration', 'body'))
            if 'Queryable' not in attrs:
                return match.group(0)
            def field(m):
                wrapper = 'NullableTimestamp' if m.group(3).startswith('Option<') else 'Timestamp'
                return m.group(1) + '#[diesel(deserialize_as = jiff_diesel::' + wrapper + ')]\n' + m.group(0)
            body = re.sub(r'^([ \t]*)((?:pub(?:\([^)]*\))?\s+)?\w+:\s*)(Option<(?:jiff::)?Timestamp>|(?:jiff::)?Timestamp)(,)', field, body, flags=re.M)
            return attrs + declaration + body + '}'
        text = row_pattern.sub(rows, text)
        def bind(match, arg):
            return match.group(0) + (('(' + arg + ').to_diesel()') if 'Timestamptz' in match.group(1) else arg) + ')'
        text = calls(text, r'\.bind::<([^()]*?)>\(', bind)
        if timestamp_columns:
            pattern = r'(\b(?:' + '|'.join(sorted(timestamp_columns)) + r')\.(?:eq|ne|lt|le|gt|ge))\('
            def expression(match, arg):
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
                name = relative.parts[1]
                sql_crates[name] = sql_crates.get(name, False) or relative.parts[2] == 'src'
    for name, production in sql_crates.items():
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
