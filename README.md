# 🛰️ NBody Labs X Range Submissions

Welcome to the automated triage and peer-review portal for the **NBody Labs Red-Teaming Range**.

Here, security learners and researchers submit their Bug Bounty Reports as Pull Requests. Our automated **AI Triage Bot** reviews each submission against our **25-point industry triage rubric**, scores your report, and posts detailed feedback directly on your PR.

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
   cp templates/REPORT_TEMPLATE.md submissions/challenge-01/<your-handle>-report.md
   ```
2. Fill out the report thoroughly with your findings from the target lab ([`nbodylabs-0xrange`](https://github.com/rum1887/nbodylabs-0xrange)).
3. Make sure you document:
   * Exact prompt inputs and model configurations
   * Empirical reliability over multiple trials (e.g. success rate over N attempts)
   * The distinction between **REACHED** (context ingestion), **HIJACKED** (tool call attempt), and **LEAKED** (account mutation)
   * Forensic logs or audit artifacts

### Step 3: Open a Pull Request
1. Commit and push your report to your fork:
   ```bash
   git checkout -b submission-challenge-01
   git add submissions/challenge-01/<your-handle>-report.md
   git commit -m "Submit Challenge 01 report by <your-handle>"
   git push origin submission-challenge-01
   ```
2. Open a Pull Request against `main` of this repository.

### Step 4: Automated Review & Triage
Within 30–60 seconds, our **AI Triage Bot** will:
* Evaluate your report across the 5 rubric dimensions.
* Assign a total score (out of 25) and triage band (Grade A to Grade D).
* Leave a comprehensive review comment on your PR with actionable guidance on what was strong and what gaps need addressing.

---

## 📊 Evaluation Standards
* Review the [25-Point Triage Rubric](docs/RUBRIC.md) to understand how points are awarded.
* Review [Worked Examples & Gap Analysis](docs/EXAMPLES.md) to see the difference between an accepted report and a rejected one.
