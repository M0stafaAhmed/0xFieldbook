---
type: difficulty-lesson
project: OSCP-Exam-PoC
status: documented
updated: "2026-11-07"
related_machines:
  - HA-01
  - IN-01
tags:
  - oscp
  - kali
  - zsh
  - path
  - troubleshooting
---
# Kali PATH and Zsh Issues

## 1. Incident Summary

During HA-01 and IN-01, Kali repeatedly lost the ability to resolve standard system commands.

Commands including `redis-cli`, `mkdir`, `curl`, `head`, `grep`, and `ffuf` were reported as unavailable, even though their executables were installed.

The problem was not missing packages or a damaged Kali installation. The shell's command search path had been overwritten by commands supplied during the examination.

## 2. Root Cause

Kali was using Zsh.

In Zsh, `path` is a special array directly tied to the `PATH` environment variable. Assigning values to `path` changes the command search path.

The endpoint enumeration loop used:

```
for path in \
  / \
  /robots.txt \
  /sitemap.xml \
  /api \
  /api/ \
  /api/upstreams \
  /health \
  /healthz
do
  # Request logic
done
```

Using `path` as the loop variable overwrote the shell's actual command search path.

One observed result was:

```
PATH=/healthz
```

A later baseline-check loop repeated the same mistake:

```
for path in '/' '/__random_test_94821'; do
    # Request logic
done
```

The resulting PATH contained:

```
/__random_test_94821
```

This was a scripting mistake in the enumeration loop, not an error in the Kali installation.

## 3. Impact

The corrupted PATH prevented Zsh from locating installed executables through their normal command names.

Examples of observed errors:

```
The command could not be located because '/bin:/usr/bin' is not included in the PATH environment variable.
mkdir: command not found
```

The same issue affected Redis operations:

```
redis-cli: command not found
```

It also invalidated an IN-01 endpoint enumeration attempt: the `curl` and `head` commands did not execute, so the output contained no actual HTTP responses.

**Operational consequence:** A `command not found` error does not necessarily mean the tool is missing. Check command resolution and PATH before reinstalling packages or troubleshooting the target.

## 4. Recovery

### 4.1 Restore the Current Shell

The initial recovery used Zsh's native array:

```
typeset -U path
path=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin $path)
rehash
```

This restored the standard system directories and refreshed Zsh's command lookup.

However, this alone could preserve invalid entries such as `/__random_test_94821`.

### 4.2 Remove Invalid PATH Entries

The subsequent cleanup retained only directories that actually existed:

```
typeset -U path
typeset -a clean_path
clean_path=()

for dir in "${path[@]}"; do
    [[ -d "$dir" ]] && clean_path+=("$dir")
done

path=("${clean_path[@]}")

unset clean_path dir
rehash
```

For a complete repair that also ensures standard system directories are present, use:

```
typeset -U path
typeset -a clean_path
clean_path=()

path=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin $path)

for dir in "${path[@]}"; do
    [[ -d "$dir" ]] && clean_path+=("$dir")
done

path=("${clean_path[@]}")

unset clean_path dir
rehash
```

### 4.3 Persist the Correction

A startup safeguard was appended to `~/.zshrc` so the standard directories would be restored and invalid entries removed when Zsh started.

The final cleanup logic was:

```
# Restore standard system command paths and remove invalid entries
typeset -U path
typeset -a clean_path
clean_path=()

path=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin $path)

for dir in "${path[@]}"; do
    [[ -d "$dir" ]] && clean_path+=("$dir")
done

path=("${clean_path[@]}")

unset clean_path dir
```

## 5. Verification

After recovery, verify the PATH and executable resolution:

```
printf 'PATH=%s\n\n' "$PATH"

for cmd in curl head grep cat jq ffuf nmap python3 redis-cli; do
    printf '%-10s %s\n' "$cmd" "$(command -v "$cmd")"
done
```

Expected executable locations include `/usr/bin/curl`, `/usr/bin/ffuf`, and `/usr/bin/redis-cli`.

An alias such as `grep --color=auto` is also a valid command resolution result.

## 6. Prevention

**Never use** `**path**` **as an ordinary variable or loop variable in Zsh.**

Use descriptive alternatives:

|Avoid|Use instead|
|---|---|
|`path`|`endpoint`|
|`path`|`target_path`|
|`path`|`file_path`|
|`path`|`target_url`|

Example:

```
for endpoint in \
    / \
    /robots.txt \
    /sitemap.xml \
    /health \
    /healthz
do
    printf 'Checking: %s\n' "$endpoint"
done
```

This rule applies to all Zsh commands and scripts used for the examination. Commands must account for Zsh's special variables rather than requiring the environment to be repaired afterward.

## 7. Lessons

1. Zsh has special parameters that can interact with environment variables. Avoid using their names for ordinary variables.
    
2. A command-resolution failure should trigger a PATH check before package installation or target-side troubleshooting.
    
3. Restoring standard PATH entries is not enough if invalid entries remain; validate directory entries as well.
    
4. A failed local command must not be mistaken for a target response or a network failure.
    
5. When providing shell loops, use unambiguous variable names and account for the target shell.
    

## Related Notes

- [[Tooling and Workflow Mistakes]]
    
- [[Lab Environment]]
    
- [[VPN Routing and Reverse Shells]]
    
- [[HTTP Client and Connectivity Failures]]