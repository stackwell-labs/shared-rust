# shared-rust

## Issues

Issues live in the `shared-rust` tracker in amber-issues, never in files: do not add
`issues/*.md`. Refer to an issue as `shared-rust#N` in commits, code comments and
docs. Use the `amber-issues` CLI. On the box it is installed and configured,
and `amber-issues whoami` prints `machine:…`: agents act as the agents'
client, which holds Triage.

- **Find work:** `amber-issues list shared-rust --status open` (or `decided`),
  `amber-issues search shared-rust <text>`, `amber-issues show shared-rust#N`. `show` prints
  the body, the links (a `blocked_by` means wait for that issue) and the
  history.
- **Decisions are the requirements.** A `decided` issue's decision, and the
  "Decided on <date>" sections in its body, say what to build; where several
  differ, the latest wins. Do not record a decision the owner has not made:
  a question for the owner goes in a comment, with the options and your
  recommendation, and the issue stays open.
- **Fixed:** after the fixing commit is pushed,
  `amber-issues close shared-rust#N --fixed amber-git:shared-rust@<40-hex sha>`.
- **Partly fixed:** rewrite the body to say what remains:
  `amber-issues edit shared-rust#N --body-file <file>`. The old body stays in the
  history.
- **Not doing it:** `amber-issues close shared-rust#N --wontfix "<why>"`. Folded into
  another issue: `amber-issues close shared-rust#N --duplicate shared-rust#M`.
- **Found something else:** stay in scope and file it:
  `amber-issues file shared-rust --title "<title>" --kind <kind> --area <tag>
  --body-file <file>`. A kind is one of bug, gap, design, question,
  performance, docs, chore, plan.
- **Blocked:** record it on the blocked issue,
  `amber-issues link shared-rust#N --blocked-by shared-rust#M`, and `unlink` the same way
  when it no longer blocks.
- **Progress notes** (an unfinished attempt, what was tried) go in
  `amber-issues comment shared-rust#N "<text>"`.

Dates are the service's today: a fix closed today is dated today, and
backdating is Admin-only.
