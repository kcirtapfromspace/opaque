"""Discover literal Rust source edges without treating strings/tests as modules.

This is a source-scope reader, not a Rust compiler. Platform/feature conditions
remain conditional; unsupported source-generating expressions fail closed.
The collector separately audits actual LLVM mappings before filtering them.
"""
from pathlib import Path
import json
import re


RAW = re.compile(r'(?:br|cr|r)(#*)"')
STRING = re.compile(r'(?:b|c)?"')
CHAR = re.compile(r"(?:b)?'(?:\\(?:u\{[0-9A-Fa-f]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\])'")
WORD = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z_0-9]*')


class ScopeError(ValueError):
    pass


def tokens(text):
    result, i = [], 0
    while i < len(text):
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end + 1
        elif text.startswith("/*", i):
            depth, i = 1, i + 2
            while depth and i < len(text):
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            if depth:
                raise ScopeError("unterminated Rust comment")
        else:
            raw = RAW.match(text, i)
            string = STRING.match(text, i)
            char = CHAR.match(text, i)
            word = WORD.match(text, i)
            if raw:
                start = raw.end()
                close = '"' + raw[1]
                end = text.find(close, start)
                if end < 0:
                    raise ScopeError("unterminated Rust raw string")
                result.append(("string" if text[i] == "r" else "opaque", text[start:end]))
                i = end + len(close)
            elif string:
                start = i
                i = string.end()
                while i < len(text):
                    if text[i] == "\\":
                        i += 2
                    elif text[i] == '"':
                        i += 1
                        break
                    else:
                        i += 1
                else:
                    raise ScopeError("unterminated Rust string")
                # Decode only when used as a source path. Rust strings in normal
                # code can contain Rust-specific escapes that JSON cannot read.
                result.append(("quoted" if text[start] == '"' else "opaque", text[start:i]))
            elif char:
                result.append(("opaque", char[0]))
                i = char.end()
            elif word:
                result.append(("word", word[0].removeprefix("r#")))
                i = word.end()
            else:
                result.append(("punct", text[i]))
                i += 1
    return result


def literal(token):
    kind, value = token
    if kind == "string":
        return value
    if kind == "quoted":
        try:
            return json.loads(value)
        except ValueError as error:
            raise ScopeError("unsupported Rust source path escape") from error
    raise ScopeError("Rust source path must be a literal string")


def group(ts, index):
    pairs = {"(": ")", "[": "]", "{": "}"}
    opening = ts[index][1]
    if ts[index][0] != "punct" or opening not in pairs:
        raise ScopeError("expected Rust token group")
    stack = [pairs[opening]]
    for end in range(index + 1, len(ts)):
        kind, value = ts[end]
        if kind != "punct":
            continue
        if value in pairs:
            stack.append(pairs[value])
        elif value in pairs.values():
            if value != stack.pop():
                raise ScopeError("unbalanced Rust token group")
            if not stack:
                return ts[index + 1:end], end + 1
    raise ScopeError("unterminated Rust token group")


def cfg_value(ts):
    """Evaluate only test=false; None means a native/feature condition."""
    if ts == [("word", "test")]:
        return False
    if len(ts) >= 3 and ts[0][1] in {"all", "any", "not"} and ts[1][1] == "(":
        inner, end = group(ts, 1)
        if end != len(ts):
            return None
        parts, start, i = [], 0, 0
        while i < len(inner):
            if inner[i][0] == "punct" and inner[i][1] in "([{":
                _, i = group(inner, i)
            elif inner[i] == ("punct", ","):
                parts.append(cfg_value(inner[start:i]))
                start = i = i + 1
            else:
                i += 1
        if start < len(inner):
            parts.append(cfg_value(inner[start:]))
        name = ts[0][1]
        if name == "not":
            return None if len(parts) != 1 or parts[0] is None else not parts[0]
        if name == "all":
            return False if False in parts else None if None in parts else True
        return True if True in parts else None if None in parts else False
    return None


def effective_attributes(attrs):
    result = []
    for attr in attrs:
        if not attr or attr[0][1] != "cfg_attr":
            result.append(attr)
            continue
        inner, _ = group(attr, 1)
        parts, start, i = [], 0, 0
        while i < len(inner):
            if inner[i][0] == "punct" and inner[i][1] in "([{":
                _, i = group(inner, i)
            elif inner[i] == ("punct", ","):
                parts.append(inner[start:i])
                start = i = i + 1
            else:
                i += 1
        if start < len(inner):
            parts.append(inner[start:])
        if len(parts) < 2:
            raise ScopeError("invalid cfg_attr source scope")
        condition = cfg_value(parts[0])
        if condition is True:
            result.extend(effective_attributes(parts[1:]))
        elif condition is None and any(part and part[0][1] in {"cfg", "path", "cfg_attr"} for part in parts[1:]):
            raise ScopeError("conditional Rust cfg/path attributes require explicit scope support")
    return result


def runtime_sources(root, entries):
    """Return exact reached files and unconditional function-bearing files.

    entries are Cargo lib/bin roots. Shared files never grant directory-wide
    ownership, and test-only paths do not enter the production graph.
    """
    root = Path(root).resolve(strict=True)
    reached, required, visited = set(), set(), set()

    def checked(path):
        path = Path(path)
        resolved = path.resolve()
        if not resolved.is_relative_to(root) or any(p.is_symlink() for p in [path, *path.parents] if p.is_relative_to(root)):
            raise ScopeError("Rust source edge escapes workspace or follows a symlink")
        if "target" in resolved.relative_to(root).parts or not resolved.is_file():
            raise ScopeError("Rust source edge is missing or generated")
        return resolved

    def visit(path, module_dir, unconditional):
        path = checked(path)
        key = (path, module_dir, unconditional)
        if key in visited:
            return
        visited.add(key)
        if scan(tokens(path.read_text()), path, module_dir, path.parent, unconditional) is not False:
            reached.add(path)

    def scan(ts, path, module_dir, attribute_dir, unconditional):
        i, attrs = 0, []
        while i < len(ts):
            kind, value = ts[i]
            if value == "#" and kind == "punct" and i + 1 < len(ts):
                inner_attribute = ts[i + 1][1] == "!"
                offset = i + 2 if inner_attribute else i + 1
                if offset < len(ts) and ts[offset][1] == "[":
                    attr, i = group(ts, offset)
                    if inner_attribute:  # Applies to this whole module/file.
                        for effective in effective_attributes([attr]):
                            if effective and effective[0][1] == "cfg" and len(effective) > 1:
                                condition, _ = group(effective, 1)
                                value = cfg_value(condition)
                                if value is False:
                                    return False
                                unconditional &= value is True
                        continue
                    attrs.append(attr)
                    continue
            active, certain, source_path = True, unconditional, None
            for attr in effective_attributes(attrs):
                if attr and attr[0][1] == "cfg" and len(attr) > 1:
                    inner, _ = group(attr, 1)
                    condition = cfg_value(inner)
                    active &= condition is not False
                    certain &= condition is True
                if attr and attr[0][1] == "path":
                    if len(attr) != 3 or attr[1][1] != "=":
                        raise ScopeError("unsupported Rust path attribute")
                    source_path = literal(attr[2])
            if kind == "word" and value == "mod" and i + 2 < len(ts) and ts[i + 1][0] == "word":
                name, ending = ts[i + 1][1], ts[i + 2][1]
                if ending == ";":
                    if active:
                        if source_path is not None:
                            child = checked(attribute_dir / source_path)
                            # #[path] overrides the normal foo.rs -> foo/
                            # ownership rule; rustc resolves children beside it.
                            child_dir = child.parent
                        else:
                            candidates = [module_dir / (name + ".rs"), module_dir / name / "mod.rs"]
                            present = [candidate for candidate in candidates if candidate.is_file()]
                            if len(present) != 1:
                                raise ScopeError("missing or ambiguous Rust module source")
                            child, child_dir = present[0], module_dir / name
                        visit(child, child_dir, certain)
                    i, attrs = i + 3, []
                    continue
                if ending == "{":
                    inner, i = group(ts, i + 2)
                    if active:
                        child_dir = attribute_dir / source_path if source_path is not None else module_dir / name
                        scan(inner, path, child_dir, child_dir, certain)
                    attrs = []
                    continue
            if kind == "word" and value == "include" and i + 2 < len(ts) and ts[i + 1][1] == "!":
                args, i = group(ts, i + 2)
                if active:
                    if args and args[-1] == ("punct", ","):
                        args = args[:-1]
                    if len(args) != 1:
                        raise ScopeError("dynamic include! source cannot silently leave coverage scope")
                    child = checked(path.parent / literal(args[0]))
                    visit(child, child.parent, certain)
                attrs = []
                continue
            if kind == "word" and value == "macro_rules":
                # Definitions may never be expanded. Source-generating macros
                # need compiler-backed scope support, not speculative ownership.
                end = i + 1
                while end < len(ts) and ts[end][1] not in "([{":
                    end += 1
                if end < len(ts):
                    body, end = group(ts, end)
                    if active and any(body[n:n + 2] == [("word", "include"), ("punct", "!")] for n in range(len(body))):
                        raise ScopeError("macro-defined include! requires explicit scope support")
                    i, attrs = end, []
                    continue
            if kind == "word" and value == "fn" and active and certain:
                # A declaration without a body emits no executable mapping.
                j = i + 1
                while j < len(ts) and ts[j] not in {("punct", ";"), ("punct", "{")}:
                    if ts[j][0] == "punct" and ts[j][1] in {"(", "["}:
                        _, j = group(ts, j)
                    else:
                        j += 1
                if j < len(ts) and ts[j][1] == "{":
                    required.add(path)
            if kind == "punct" and value in "([{":
                inner, i = group(ts, i)
                if active:
                    scan(inner, path, module_dir, attribute_dir, certain)
                if value == "{":
                    attrs = []
                continue
            if value == ";":
                attrs = []
            i += 1

    for entry in entries:
        source = checked(root / entry)
        visit(source, source.parent, True)
    return {"sources": {p.relative_to(root).as_posix() for p in reached},
            "required": {p.relative_to(root).as_posix() for p in required}}
