# CI runner minutes

Every push runs the whole CI matrix on a shared runner. This report says what
that costs, per push and per day, without changing what the build gates on.

The `CI runner minutes` job in `.github/workflows/ci.yml` collects the run and
job records the GitHub Actions API already holds, sums the runner time of the
completed jobs, and writes the report. The job runs with `actions: read` and
the built-in token, it only reads, and it is marked `continue-on-error`, so a
report that cannot be produced never turns a green build red.

The job uploads four files as the `qpx-ci-runner-minutes` artifact:

- `runs.jsonl`: one record per workflow run the report looked at.
- `jobs.jsonl`: one record per job of those runs.
- `collection.json`: what the collector read, and what it left out.
- `runner-minutes.json`: the report itself.

The report covers one workflow: the one that produced the run. The day view
therefore totals that workflow's runs, not every workflow of the repository.
The other workflows of a push (the codeql, security-qa and structure checks)
cost a few minutes each and are not in this number.

## What the numbers mean

The report keeps three quantities apart, because they answer different
questions:

- `runner_minutes` is the summed wall-clock time each completed job occupied
  a runner. This is the number that costs runner time. Jobs run in parallel,
  so the sum is larger than the run's elapsed time.
- `elapsed_minutes` is the wall-clock span from the first counted job's start
  to the last one's completion. It is how long the run took, not what it
  cost.
- `queue_delay_minutes_max` is the longest gap between a run starting and one
  of its jobs starting. The wait before the first job is neither runner time
  nor elapsed time, so it is reported on its own.

A failed job is counted: it consumed runner time. A skipped job is not
counted and does not make the total partial, because it never ran. A job that
is still queued or running, or that has no usable start or completion
timestamp, is not counted, and it marks the total `partial` with the reason.

The reporting job is the one exception: it is running while it reports, so it
is counted separately as `jobs_reporter_unfinished` and never makes the run
total partial. The flag therefore means "the push still had unfinished work
when the report was taken", not "the reporter had not finished yet". The
exemption covers that one job of the reported run: another run's reporting job
is ordinary unfinished work, so a second push or pull-request run in flight
keeps the day total partial. The reporter's own minutes are not in the run's
number; they appear in a later report's breakdown of the same run, once the
job has completed.

## Partial totals

The report is taken while the run is still going, so the jobs that have not
finished yet are missing from it. The per-run total is therefore a lower
bound at capture time, and it says so: `partial` is true and
`partial_reasons` names what is missing. The report is bound to the head SHA
it was taken from, the workflow, the run identifier, and the capture time, so
a number can always be traced back to the run it describes. A run whose
records were not collected at all is reported as partial too, never as a run
that cost nothing.

The `runs` list gives every collected run its own line, so a later report
carries the final cost of the earlier pushes of the day, including the
reporting job's own minutes. The day view converges on the true total the
same way: each run's collection includes the jobs of every run of that
workflow created on that UTC day, so a later run's report counts the earlier
runs' finished jobs. The day is the UTC day a job *started* on, so a job that
runs across midnight belongs to the day it started. A run that was created
before the day and was still running inside it is not part of the day view.

The collector keeps at most 100 runs of the day. If the day holds more, the
oldest are dropped, the day total is marked partial, and `collection.json`
records how many were left out. The run being reported is never dropped: a
report that lost its own run could not say what it measured.

## Reproducing a report

The report is a pure function of the collected records and of the collection
note, so the artifact can be re-summed without the API:

```bash
python3 scripts/ci-runner-minutes.py report \
  --runs target/ci-runner-minutes/runs.jsonl \
  --jobs target/ci-runner-minutes/jobs.jsonl \
  --collection target/ci-runner-minutes/collection.json \
  --run-id <run id> \
  --out /tmp/runner-minutes.json
```

The collection note matters: it names the reporting job, whose own unfinished
state is exempt from the reported run's total, and it records what the
collector left out. Without it the re-summed report differs from the
published one.

`scripts/test-ci-runner-minutes.py` checks the calculation on synthetic
records: overlapping jobs, queued and running jobs, failures, skipped jobs,
missing timestamps, the queue delay, the midnight boundary, the reporting
job's own unfinished state, a run whose records were not collected, and a day
with more runs than the collector keeps.

## What the report does not do

It does not gate anything, it does not request or expose a secret, and it
does not add an external service. It stores nothing: the day total is
recomputed from the API on each run, so there is no durable daily ledger
behind it.
