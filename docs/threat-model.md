# Threat model

What `fim` defends, against whom, how, and what it does not defend. The controls are those of
[PLAN.md](../PLAN.md) section 3 and decisions D2 to D14 as built; every row names the test that
holds the control in place (`tests/<file>::<test>`; a test checks that each named test exists).
The README's Limitations section repeats the residual risks in plain words.

CWE numbers are given only for the tool's own controls, never for findings. They were written
from memory of the CWE list and not re-checked against the live list, because this project's
tooling reaches PyPI only; check them before quoting them elsewhere.

## 1. What `fim` is, and the one thing it protects

`fim` records the state of paths you configure (type, size, modification time, SHA-256, POSIX
permission bits or Windows attribute bits, owner ids, link targets) in a baseline file signed with
an HMAC key, and later reports what differs. It is a detective control for a machine you own: it
tells you that a file changed. It does not prevent a change, restore a file, or say who did it.

Assets, in the order that matters:

1. **The integrity of the baseline.** If an attacker can change the baseline without being
   noticed, every later check is meaningless.
2. **The secrecy of the HMAC key.** Whoever can read the key can forge a baseline.
3. **The correctness and safety of what the tool prints.** A report that can be spoofed, or that
   can attack the person reading it, is worse than none.
4. **The host.** The tool must not damage the files it watches or the machine it runs on.

## 2. Who can do what

| Actor | Can | Cannot (by assumption) | What `fim` gives you against them |
|---|---|---|---|
| A. Intruder who changes monitored files | write, delete, create, chmod, replace with links | read the key, write the key directory | A `check` reports every change it can see (hash, size, type, permission, link). |
| B. Intruder who also edits the baseline file | everything in A, plus write the baseline | read the key | Exit code 3: the HMAC does not verify. Nothing in a baseline is parsed before it verifies. |
| C. Intruder who puts an older, validly signed baseline back | everything in B, plus copy an earlier baseline | read the key, write the key directory | Exit code 3: the rollback anchor names a different sequence or payload digest. |
| D. Intruder who can also write the key directory | everything in C, plus delete files next to the key | read the key | The anchor can be deleted. That is a **warning**, not a refusal; a rollback then goes unnoticed. |
| E. Intruder with the tool's own privileges | read the key, write anything the tool writes | nothing | **No protection.** They can forge a baseline that verifies. Run the monitor and key under a separate account, or keep the key on media the watched account cannot read. |
| F. Someone who can create files with hostile names | plant a name with terminal escapes, bidi controls, newlines, formula prefixes | - | Every name is escaped before it is shown; the baseline keeps the exact name. |
| G. Someone who can edit the configuration file | add excludes, lower severities | write the baseline | `check` and `watch` scan with the policy stored in the signed baseline, not the configuration. A different configuration is reported as `policy_drift`. |
| H. Someone who can race the tool | swap a file for a link or a FIFO between two system calls, grow or replace a file while it is hashed | - | The race is reported (`unstable`, `vanished`) and never trusted. |

## 3. Data flow and trust boundaries

```
 monitored paths --read-only--> fs/observe.py --> scanner --> diff --> renderers --> stdout / report file
   (untrusted names,                                ^
    untrusted content)                              | policy comes from the baseline
 config file --no-follow, capped--> config loader   |
 key file --no-follow, 0600, capped, outside roots--> keystore --> HMAC --> baseline codec
 baseline file --size cap, then MAC, then parse-----------------------------^
 anchor file --next to the key, signed, checked after the baseline MAC
```

Everything that comes from the filesystem is hostile: names, link targets, content, sizes, times.
Everything that is the tool's own (the key, the baseline, the anchor, the configuration) is read
through `fs/safe_files.py`, which refuses links, special files and oversize files before reading.
`fs/observe.py` is the only module that touches monitored files and it has no write call at all
(the architecture checker bans them in that file).

## 4. Threats, controls and what is left

| # | Threat | Control | Residual risk, out of scope | Evidence |
|---|---|---|---|---|
| T1 | A monitored file is changed | SHA-256 plus metadata compared with the signed baseline; findings carry kind, severity and confidence | Polling: a change made and undone between two runs is missed. Only what is recorded is compared (no ACLs, ADS, xattrs). | `tests/test_check.py::test_init_key_baseline_change_check_reports_each_change_and_exits_1` |
| T2 | The baseline is edited or replaced without the key (CWE-354) | HMAC-SHA256 over format, version, key id and payload; size cap first, then envelope, then MAC, then the payload parser; any failure is exit 3 | None known for an attacker without the key. | `tests/test_baseline_codec.py::test_the_payload_parser_is_never_called_before_the_mac_verifies`, `tests/test_baseline_codec.py::test_one_flipped_byte_anywhere_in_the_payload_is_refused`, `tests/test_check.py::test_a_tampered_baseline_is_exit_3_through_the_cli` |
| T3 | An older valid baseline is put back (rollback) | The anchor next to the key holds the latest sequence and payload digest, signed with its own domain prefix; `check` and `watch` exit 3 on a mismatch | The anchor file can be deleted by anyone who can write the key directory: that is a warning, not a refusal. Moving a baseline file loses its anchor for the same reason (the anchor is bound to the baseline's path). | `tests/test_check.py::test_an_older_validly_signed_baseline_put_back_is_exit_3_a_rollback`, `tests/test_check.py::test_a_deleted_anchor_is_only_a_warning_and_the_check_runs`, `tests/test_baseline_codec.py::test_an_anchor_for_another_baseline_is_refused` |
| T4 | The configuration is edited to hide paths | The policy used by `check` and `watch` is the one inside the signed baseline (D4); a differing configuration is a `policy_drift` finding | None for scope. But `key_file` in the configuration is trusted input: someone who can edit the configuration **and** the baseline can point `check` at a key of their own and a baseline signed with it (there is then no anchor, only a warning). Pass `--key-file` explicitly from a place the watched account cannot write. | `tests/test_check.py::test_a_configuration_that_adds_an_exclude_does_not_hide_changes_and_reports_drift` |
| T5 | The attacker has the tool's own privileges | none possible: they can read the key and write a baseline that verifies | Stated, not mitigated. Use a separate account or media for the key, and write the baseline where the watched account cannot. | not testable; see README Limitations |
| T6 | A hostile name attacks the terminal, a log or a SIEM (CWE-150, CWE-117) | One sanitiser (`core/sanitize.py`) escapes controls, bidi and format characters, line and paragraph separators, private-use and unassigned code points, lone surrogates and undecodable bytes before any output; JSON and JSONL are ASCII-only on top; the baseline stores the exact path through canonical JSON | Characters that look like others or look blank but are letters or marks are not escaped (Cyrillic "a", Hangul filler U+3164, Braille blank U+2800). | `tests/test_sanitize.py::test_every_codepoint_escapes_safely_and_round_trips`, `tests/test_check.py::test_a_hostile_file_name_is_escaped_in_the_table_and_the_json`, `tests/test_render_events.py::test_a_hostile_name_is_one_line_with_no_raw_control_or_bidi_character` |
| T7 | CSV formula injection (CWE-1236) | every cell is escaped, quoted, and a leading `=`, `+`, `-`, `@`, tab or carriage return gets a `'` prefix | CSV is lossy by design; use JSON for exact data. | `tests/test_render_events.py::test_a_cell_that_could_be_a_formula_is_neutralised` |
| T8 | Symlink, junction and reparse-point tricks (CWE-59): escaping a root, looping, writing through a link | Links are recorded, never followed or entered (the `files` policy only hashes a file target and never enters a linked directory); roots that are links are refused; the tool's own files are opened without following and compared by device and inode with the earlier `lstat`; writes go to a new temporary file and are published with a hard link or `os.replace`, which never writes through a link | A parent directory swapped between the checks and the rename. On Windows the open itself has no no-follow flag; the identity comparison is the guard. | `tests/test_scanner_real.py::test_symlinks_are_recorded_as_links_and_never_entered`, `tests/test_safe_files.py::test_writing_never_goes_through_a_symlink_even_with_force`, `tests/test_safe_files.py::test_a_path_swapped_between_lstat_and_open_is_refused` |
| T9 | A file is swapped, grown or removed while it is read (CWE-367) | `lstat` identity compared with the open descriptor, a second `fstat` after the read, one retry, then `unstable`; a file that vanished is `vanished`; neither is a crash or a silent skip | Changes between the scan and the report. | `tests/test_observe.py::test_a_file_replaced_by_another_during_the_scan_is_unstable`, `tests/test_observe.py::test_two_changed_passes_in_a_row_are_unstable_and_give_no_hash` |
| T10 | Resource exhaustion: huge trees, deep trees, huge files, huge baselines or configurations, YAML bombs (CWE-400) | Every bound is a named constant with a hard ceiling in `core/limits.py`; hitting a scan limit marks the run incomplete (exit 4) and is never reported as clean; an oversize baseline is refused unread (exit 3), an oversize configuration or key file is refused unread (exit 2) | A tree just under the limits still costs memory and time; see [performance.md](performance.md). | `tests/test_scanner_virtual.py::test_hitting_a_limit_is_never_reported_as_complete_for_any_limit`, `tests/test_limits.py::test_one_above_the_ceiling_is_refused`, `tests/test_check.py::test_a_scan_that_hits_a_limit_is_exit_4_and_says_so` |
| T11 | Unsafe YAML deserialisation (CWE-502) | a SafeLoader subclass that also refuses anchors, aliases, merge keys, custom tags, duplicate keys and multiple documents; `yaml.load` and `unsafe_load` are banned in `src/` by the architecture check | PyYAML itself is a dependency. | `tests/test_config.py::test_aliases_are_refused_with_a_hint_about_quoting_stars`, `tests/test_architecture_rules.py::test_a010_banned_module_builtin_or_api` |
| T12 | The key leaks (CWE-732 and others) | 32 random bytes in a file created `0600` (POSIX); a key readable by group or others, or owned by someone else, is refused (POSIX); the key is passed only as a file path, never in argv or the environment, never printed, never in an error; a key inside a monitored root is refused | The key file's ACL is not verified on Windows. A crash between creating and removing a temporary file can leave a `.fim-*.tmp` copy of the key in the key directory. | `tests/test_safe_files.py::test_a_key_that_group_or_others_can_access_is_refused`, `tests/test_cli_commands.py::test_no_option_takes_a_key_value`, `tests/test_app_baseline.py::test_the_key_appears_in_no_output_exception_baseline_anchor_or_log`, `tests/test_app_baseline.py::test_a_key_file_inside_a_monitored_root_is_refused_on_the_command_line` |
| T13 | A FIFO, socket or device hangs or alters the scan | Only regular files are opened; the open uses `O_NONBLOCK` on POSIX and the descriptor is checked again; other types are recorded by type | A file system that hangs on `lstat` (a dead network mount). | `tests/test_scanner_virtual.py::test_special_files_are_described_and_never_opened`, `tests/test_observe.py::test_a_descriptor_that_is_not_a_regular_file_is_never_read` |
| T14 | The tool damages the host or the watched files | `fs/observe.py` contains no write, move, chmod or delete call and no write flag (architecture check); a before and after tree-state test; the demo works only inside one temporary directory and removes it | Reading can update an access time. | `tests/test_architecture_rules.py::test_a007_write_or_mutate_api_in_observe`, `tests/test_scanner_real.py::test_scanning_changes_nothing_about_any_file_or_directory`, `tests/test_demo.py::test_the_demo_touches_only_its_own_directory_and_leaves_the_base_as_it_found_it` |
| T15 | The tool's own output files overwrite something or are written through a link | Reports and logs are new files (`O_EXCL`); an existing file needs `--force`, and a link or reparse point is refused even then; the output may not lie inside a monitored path | On a file system without hard links (FAT, exFAT) the write is exclusive but not atomic: a crash can leave a partial file. | `tests/test_check.py::test_output_writes_a_new_file_and_refuses_to_replace_one_without_force`, `tests/test_safe_files.py::test_a_file_created_after_the_check_is_not_overwritten`, `tests/test_safe_files.py::test_without_hard_links_the_file_is_created_directly_and_exclusively` |
| T16 | A hostile path argument (UNC, device, URL-like, drive-relative, `..`) | Every user-supplied path passes `core/pathrules.py` before any I/O. The Windows name rules apply to Windows paths only; POSIX names such as `pci0000:00` stay legal | None known. | `tests/test_app_baseline.py::test_hostile_command_line_paths_are_refused_before_any_io`, `tests/test_safe_files.py::test_hostile_and_unsupported_paths_are_refused_everywhere` |
| T17 | A malicious or damaged dependency or build step | One runtime dependency (PyYAML); no network, no subprocess, no `pickle`, `eval` or dynamic import in `src/` (architecture check); CI pins action majors; `pip-audit` and `bandit` are run at release | A compromised PyPI package or GitHub Action. | `tests/test_architecture_rules.py::test_a010_banned_module_builtin_or_api`, `tests/test_ci_policy.py::test_the_real_workflow_satisfies_the_policy` |

## 5. Out of scope in version 1

- Kernel hooks, inotify, ReadDirectoryChangesW, eBPF: `watch` polls.
- Windows ACLs and owners, alternate data streams, POSIX ACLs, extended attributes, file
  capabilities, SELinux labels.
- Restoring or quarantining a file, or any other automatic response.
- A network agent, a server, a GUI.
- Protecting against an attacker with the tool's own privileges (T5).
- Detecting a mapped network drive as such (`one_file_system` compares device numbers).

## 6. How to deploy so the controls mean something

1. Keep the key where the watched account cannot read it: another account, or removable media.
   The key directory also holds the anchors, so deny that account write access there too.
2. Write the baseline where the watched account cannot replace it, or accept that T2 and T3 are
   then only as strong as the key and the anchor.
3. Run `check` or `watch` as the account that owns the key, from a location the watched account
   cannot modify.
4. Make a new baseline (`fim baseline --force`) after every deliberate change, and keep the old
   key and baseline until you have verified the new one.
5. Send `watch` output (JSONL) to a collector the watched machine cannot rewrite: see
   [siem-mapping.md](siem-mapping.md).
