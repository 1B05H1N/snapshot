# snapshot.sh

A lightweight, modular security scanner for Git repositories.

## Features
- **Secrets discovery** (regex + entropy-based)
- **Dependency vulnerability checks** (OSV.dev)
- **Infrastructure-as-Code validation** (Terraform, Kubernetes)
- **Branch protection verification** (GitHub)
- Modular design for easy extension

## How Secret Detection Works: Shannon Entropy

This tool uses [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) to help detect secrets that may not match common patterns (like API keys or passwords). Shannon entropy measures the randomness or unpredictability in a string:

- **High entropy** (e.g., random base64 or hex strings) is typical of secrets, tokens, or cryptographic keys.
- **Low entropy** (e.g., English words, predictable values) is typical of non-secret data.

The script calculates the entropy of candidate strings and flags those above a configurable threshold (default: 4.0 bits/char) as potential secrets.

**References:**
- [Wikipedia: Entropy (information theory)](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [Shannon Entropy Intuition (PDF)](https://pages.cs.wisc.edu/~sriram/ShannonEntropy-Intuition.pdf)
- [The Hardcore Coder: Calculating Entropy in Python](https://thehardcorecoder.com/2021/12/21/calculating-entropy-in-python/)

## How Secrets Scanning Works

The secrets scanner uses two main techniques:

1. **Pattern Matching:**
   - Scans files for common secret patterns (e.g., `AWS_KEY`, `API_KEY`, `SECRET=...`, `PASSWORD=...`, etc.) using regular expressions.
   - If a match is found, the line and pattern are reported as a potential secret.

2. **Entropy Analysis:**
   - Uses [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) to detect high-entropy strings (random-looking values typical of secrets, tokens, or cryptographic keys).
   - Strings above a configurable entropy threshold (default: 4.0 bits/char) are flagged as potential secrets, even if they don't match a known pattern.

This dual approach helps catch both obvious and subtle secrets in your codebase.

## How the IaC Scanner Works

The IaC (Infrastructure-as-Code) scanner checks for misconfigurations and security issues in:
- **Terraform** files (using [tfsec](https://aquasecurity.github.io/tfsec/))
- **Kubernetes YAML** files (using [kube-linter](https://docs.kubelinter.io/))

**How it works:**
- If `tfsec` is installed, the tool scans all Terraform files for security issues.
- If `kube-linter` is installed, the tool scans all Kubernetes YAML manifests for common misconfigurations.
- If either tool is missing, the script will warn you and skip that part of the scan.

**You do not need these tools for the rest of the scanner to work, but you will get more complete IaC security coverage if you install them.**

## How Branch Protection Detection Works

The branch protection check verifies if the current branch is protected on GitHub:

- Uses the GitHub API to check the protection status of the current branch.
- Requires a `GITHUB_TOKEN` environment variable with repo read access.
- If the branch is not protected, the tool reports a critical finding.
- If the branch is protected, it reports success.

**References:**
- [GitHub API: Branches](https://docs.github.com/en/rest/branches/branches?apiVersion=2022-11-28#get-a-branch)
- [GitHub Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-branch-protection-rules)

## Project Structure
```
.
├── snapshot.sh            # Main entrypoint script
├── lib/                   # Modular check scripts (sourced by snapshot.sh)
│   ├── scan_secrets.sh    # Secrets scanning logic
│   ├── scan_deps.sh       # Dependency vulnerability check logic
│   ├── scan_iac.sh        # IaC misconfiguration check logic
│   └── check_branch_protection.sh # Branch protection check logic
├── snapshot-test.sh       # Example/test script for the tool
├── requirements.txt       # List of required and optional dependencies
├── .gitignore             # Files and folders to ignore in git
├── LICENSE                # Project license (MIT)
├── README.md              # This documentation file
└── snapshot.log           # Log file (ignored by git)
```

- Place new checks in `lib/` and source them in `snapshot.sh`.
- `snapshot.log` is generated at runtime and ignored by git.

## Requirements
- bash (4+ recommended)
- git
- jq
- curl
- awk
- **(optional)** [tfsec](https://aquasecurity.github.io/tfsec/) (for Terraform scanning)
- **(optional)** [kube-linter](https://docs.kubelinter.io/) (for Kubernetes YAML scanning)

## Installation
1. Clone this repository:
   ```sh
   git clone <your-repo-url>
   cd <your-repo>
   ```
2. Make the main script executable:
   ```sh
   chmod +x snapshot.sh
   ```
3. (Optional) Install IaC scanning tools:
   ```sh
   brew install tfsec kube-linter
   ```

## Usage
```sh
./snapshot.sh [OPTIONS] [FILES...]
```

### Options
- `--help`             Show help message
- `--version`          Show version
- `--sarif FILE`       Output results in SARIF format
- `--skip CHECKS`      Comma-separated list of checks to skip
- `--only CHECKS`      Comma-separated list of checks to run
- `--severity LEVEL`   Minimum severity to report (informational|low|medium|high|critical)
- `--parallel`         Run checks in parallel
- `--quiet`            Reduce output verbosity
- `--verbose`          Increase output verbosity

### Example
```sh
./snapshot.sh --verbose
./snapshot.sh --only secrets,branch --severity high
./snapshot.sh --sarif results.sarif
```

## Contributing
- Fork the repo and submit pull requests.
- Add new checks by creating a new file in `lib/` and sourcing it in `snapshot.sh`.
- Run `shellcheck` on all scripts before submitting.

## License
MIT 