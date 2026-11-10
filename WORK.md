# Jot live dispatch permission — 2026-09-30

The live check's current App token cannot dispatch Jot: the all-repository
`stackwell-labs-ci` App has only Contents read and Metadata read. Prepare the
shared workflow to use `JOT_DISPATCH_APP_ID` and
`JOT_DISPATCH_APP_PRIVATE_KEY` from a separate App installed only on Jot with
Actions read/write. Existing callers pin the old shared-workflow SHA and remain
unchanged until each caller supplies the new variable and secret and updates its
pin. GitHub App creation and installation approval must happen in GitHub's
organization settings UI before this workflow is adopted.

# Prior work — Jot release acceptance, 2026-09-08

Add public reusable workflow entry points for the Jot acceptance harness. Both
the chirpauth and stackwell-labs organizations need to call them; private
source remains authenticated with the existing CI App.

Candidate builds use explicit SHAs and four real routers, with a required
browser journey. Post-release checks dispatch and await one serialized live
workflow in Jot. No caller can pass by skipping an unavailable check.

Actionlint passes for both new reusable workflows. Local positive and deliberately
broken candidates are exercised in Jot. Next: commit, pin caller workflows to
this revision, and demonstrate hosted failed-gate → skipped-publication behavior.
