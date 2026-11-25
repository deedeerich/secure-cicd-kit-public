# Dependabot in your repository: a short guide for developers

Dependabot opens pull requests that keep your dependencies current. It only updates what
`.github/dependabot.yml` tells it to read, folder by folder. Two mistakes are easy to make and
nothing warns you about them on their own:

1. **You add a manifest in a new folder** (a second `package.json`, a new `requirements.txt`, a
   Dockerfile, a Terraform module) and no entry reads that folder. Dependabot never updates it.
2. **You move or delete a manifest** and the entry still names the old folder. Dependabot fails
   that update job every week with `dependency_file_not_found`.

The kit checks both for you.

## What you see on a pull request

If your repository has the **Dependabot configuration** check (`templates/dependabot-config-check.yml`),
every pull request that touches a manifest or `.github/dependabot.yml` is checked. Other pull requests
pass in a few seconds with "nothing to check".

When something is wrong, the check fails and says exactly what to do, for example:

```text
Dependabot configuration: 1 problem(s).
  1. web/package.json is not read by any npm entry, so Dependabot never updates it.
     Fix: add "/web" to the `directories:` list of the npm entry in .github/dependabot.yml
```

The job summary also contains a corrected `.github/dependabot.yml` you can copy (it is attached to
the run as the artifact `dependabot-yml-proposed` too). Nothing is wrong with your code; only the
configuration file needs the line.

## The one-command fix

From a checkout of the kit, in your repository's root:

```bash
python3 path/to/secure-cicd-kit/scripts/dependabot_config.py generate --write   # writes .github/dependabot.yml
python3 path/to/secure-cicd-kit/scripts/dependabot_config.py check              # confirms it
```

Review the file and commit it. `discover` lists every manifest it found and every folder it left
out, with the rule.

## What the generated file does

- One entry per ecosystem (npm, pip, Maven, Gradle, NuGet, Go, Composer, Docker, Terraform, GitHub
  Actions and others), listing every folder that holds a manifest.
- Minor and patch updates arrive as **one grouped pull request** per ecosystem; majors come one by one.
- `rebase-strategy: auto`, so a pull request that conflicts with `main` is rebased for you. One that is
  merely behind `main` is asked to rebase by the kit's triage (`DEPENDABOT_TRIAGE.md` section 3b).
- GitHub Actions used by your workflows and composite actions are kept current.
- **Left out by rule:** vendored code (`node_modules`, `vendor`, `third_party`, `.venv` ...) and build
  output (`dist`, `build`, `target`, `bin`, `obj`, `.terraform`).
- **Test fixtures are held still:** a manifest under `fixtures`, `testdata` or similar gets an entry
  with `open-pull-requests-limit: 0` and every dependency ignored, so not even a security update
  changes your deliberately pinned test inputs.

## Leaving a manifest out on purpose

Give it a held entry in `.github/dependabot.yml`; the check accepts that as covered, and the choice is
visible in review:

```yaml
  - package-ecosystem: npm
    directory: "/samples/legacy-demo"
    schedule: {interval: monthly}
    open-pull-requests-limit: 0
    ignore: [{dependency-name: "*"}]
```

## When a Dependabot pull request arrives

Patch and minor updates that cannot change behaviour merge on their own once every required check
passes, only in repositories that turned auto-merge on (see `AUTOMERGE_RISKS_AND_ROLLOUT.md`).
Anything else is labelled `needs-human-review` with the reason in a comment. You do not need to type
`@dependabot rebase`; the kit does that when `main` moves.

Proof: `tests/prove_dependabot_config.py`.
