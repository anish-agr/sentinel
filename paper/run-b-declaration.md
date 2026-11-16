# Run B declaration

Run B is the replication on the Gemini API. Its stopping rule, contrasts and
multiplicity correction were fixed on 2026-08-22, before any confirmatory
session was collected. This file restates that declaration in condensed form.
The targets, contrasts and dates are as declared.

## Stopping rule

Run B collects until each arm has 787 raw denial events, $600 has been spent,
or the clock reaches 2026-08-27 06:00, whichever comes first. The monitor that
applies the rule (`paper/scripts/api/accrual_monitor.py`) reads four values:
the denial-event count per arm, the clock, the spend and the session count. It
does not compute any arm rate, override rate or contrast. Its `--selftest`
checks that each stop condition fires and that none fires early.

The budget was raised from $450 to $600 before collection. At about $0.043 per
session, a $450 cap would have stopped the run near 628 events per arm for any
yield below 0.376 events per session.

## Target

787 events per arm gives a minimum detectable effect of 9.0 points at design
effect 1.45, alpha 0.0167 (Holm, k=3), power 0.80 and a base rate of 0.30:

```
0.090 = 3.236 * sqrt(0.42 / eff)   ->   eff = 543 effective events per arm
543 * 1.45                          ->   787 raw denial events per arm
```

The target is set in events because the number of denials per session was
uncertain. The smoke run measured 0.71 per session and the pilot 0.30. The
difference came from the task mix: the smoke run walked task families in
alphabetical order, so 44.9% of its sessions were `git.*` tasks against 26.3%
in the pilot, and `git.*` tasks trigger a rule 2.52 times as often. The
family-balanced estimate is 0.37 per session.

## The pilot is excluded

An exploratory pilot of 631 sessions across 160 cells ran on 2026-08-21 and was
used to choose Run B's contrasts. It is excluded by a list of the session logs
that existed at declaration (`paper/run-b-pilot-sessions.json`), so Run B counts only
sessions collected after it.

## Design

Three anchor models and five arms (`terse`, `explain`, `padded`, `defer`,
`full`), with the arms run interleaved within each model. `MAX_STEPS` is 12, as
in the pilot.

## Contrasts

- Confirmatory: `defer` against `full`, which isolates the named override.
- Dropped for low power: `terse` against `explain`. On the pilot, 38/43 against
  34/41 gives a Newcombe interval of [-10.0, +21.1] with a minimum detectable
  difference of 21.4 points.
- Not tested: `explain` against `padded`.

The Holm correction stays at k=3 after the two contrasts were dropped. A null
result is reported as no difference detectable at this sample size, not as
evidence of no effect.

## Harness fixes before launch

Six defects found in the pilot harness were fixed before the first Run B
session: non-atomic session writes, a retry check that matched status codes as
substrings, an API-error gate with no minimum count, a table check that stopped
after the first table, a check that globbed a path that cannot exist, and a
per-cell guard check that abandoned whole cells.

## Reporting

The report gives the achieved event count per arm, the minimum detectable
effect computed from it, and any shortfall against 787.
