# 🛰️ NBody Labs: 0xRange Submissions

> **The proving ground for modern security research.**  
> *Real architectures. Modern attack surfaces. Zero artificial flags.*

Welcome to the automated triage and peer-review portal for the **NBody Labs Security Range**.

Here, security learners and researchers submit their Bug Bounty Reports as Pull Requests. Our automated **AI Triage Bot** reviews each submission against the **25-point NBody Labs triage rubric**, scores your report, and posts detailed feedback directly on your PR.

---

## 🚀 How to Submit Your Report

### Step 1: Fork & Clone
1. Fork this repository to your personal GitHub account.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/nbody-labs-x-range-submissions.git
   cd nbody-labs-x-range-submissions
   ```

### Step 2: Draft Your Report
1. Copy the standard template:
   ```bash
   cp templates/REPORT_TEMPLATE.md submissions/challenge-0x01/<your-handle>-report.md
   ```
2. Fill out the report thoroughly with your findings from the target lab ([`nbodylabs-0xrange`](https://github.com/rum1887/nbodylabs-0xrange)).
3. Make sure you document:
   * Exact prompt inputs, target models, and sampling parameters
   * Empirical reliability over multiple trials ($N$ attempts with success rate)
   * The forensic distinction between **REACHED** (context ingestion), **HIJACKED** (intent redirect/tool invocation), and **LEAKED / MUTATED** vs. **HELD** at the Human-in-the-Loop **Approval Gate**
   * Forensic logs or audit artifacts

> **Submission Constraints:**
> * Each PR must add or modify **exactly one** report file (`submissions/challenge-0xXX/<your-handle>-report.md`).
> * Maximum report file size is 64 KB. Symlinks are rejected.

### Step 3: Open a Pull Request
1. Commit and push your report to your fork:
   ```bash
   git checkout -b submission-challenge-0x01
   git add submissions/challenge-0x01/<your-handle>-report.md
   git commit -m "Submit Challenge 0x01 report by <your-handle>"
   git push origin submission-challenge-0x01
   ```
2. Open a Pull Request against `main` of this repository.

### Step 4: Automated Review & Triage
Once opened:
1. A repository maintainer will review the PR and apply the `ready-to-grade` label.
2. The **AI Triage Bot** runs automatically to:
   * Evaluate your report across the 5 rubric dimensions.
   * Assign a total score (out of 25) and triage band (Grade A to Grade D).
   * Leave a comprehensive review comment on your PR with actionable guidance on what was strong and what gaps need addressing.

---

## 📊 Evaluation Standards
* Review the [25-Point Triage Rubric](docs/RUBRIC.md) to understand how points are awarded.
* Review [Worked Examples & Gap Analysis](docs/EXAMPLES.md) to see the difference between an accepted report and a rejected one.

---

## 🛰️ About NBody Labs

**NBody Labs** is an independent venture dedicated to building the next generation of hands-on security labs, realistic ranges, and practical playgrounds for engineers, researchers, and learners.
