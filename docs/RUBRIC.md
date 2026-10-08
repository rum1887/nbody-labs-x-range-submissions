# NBody Labs Bug Bounty Evaluation Rubric (25-Point Standard)

This rubric is used by triagers and the automated GitHub Reviewer Bot to evaluate security and vulnerability reports submitted to NBody Labs 0xRange.

Security triage for autonomous agent systems differs fundamentally from traditional web application security:
* **LLMs are probabilistic**: Findings cannot be judged on "100% determinism". Top-tier reports document empirical success rates across multiple trials under specified parameters.
* **Impact must be grounded in agency and forensic stages**: Getting a model to say something prohibited is usually low severity. Forcing a model to invoke unauthorized tools, exfiltrate private data, or manipulate the **Human-in-the-Loop Approval Gate** is critical severity.

---

## Evaluation Dimensions (5 × 5 Points = 25 Points Total)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        25-POINT SCORING SYSTEM                         │
├──────────────────────────────────┬─────────────────────────────────────┤
│ Dimension                        │ Score Range                         │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 1. Technical Precision & Forensic│ 0 – 5 points                        │
│    Modeling (REACHED/HIJACKED)   │                                     │
│ 2. Empirical Reproducibility     │ 0 – 5 points                        │
│ 3. Blast Radius & Approval-Gate  │ 0 – 5 points                        │
│    Analysis (LEAKED vs. HELD)    │                                     │
│ 4. Attack Chain Engineering      │ 0 – 5 points                        │
│ 5. Remediation & Defenses        │ 0 – 5 points                        │
└──────────────────────────────────┴─────────────────────────────────────┘
```

---

### 1. Technical Precision & Forensic Modeling (0–5 Points)

Evaluates whether the report correctly models the target architecture, trust boundaries, and the **Forensic Triage Taxonomy**:
* **REACHED**: Untrusted external data successfully ingested into model context.
* **HIJACKED**: Agent objective diverted to unauthorized tool calling or private data reading.
* **LEAKED / MUTATED**: State mutation executed vs. held at the gate.

| Points | Description |
| :--- | :--- |
| **5 (Exemplary)** | Accurately models the architecture (orchestrator, tool execution loop, context windows, external sources). Rigorously applies the forensic triage taxonomy by distinguishing **REACHED** (untrusted context ingestion) vs. **HIJACKED** (intent redirect & unauthorized tool invocation). Distinguishes direct prompt injection from indirect prompt injection without vague handwaving. |
| **4 (Strong)** | Correctly identifies the vulnerability type and primary trust boundary. Distinguishes prompt injection from tool execution and separates context ingestion from secondary tool actions with minor taxonomy gaps. |
| **3 (Adequate)** | Names the vulnerability type correctly (e.g., indirect prompt injection), but threat model is generic. Lumps context ingestion and tool execution together without distinguishing REACHED vs. HIJACKED. |
| **2 (Weak)** | Confuses core security concepts (e.g., calls prompt injection "SQL injection" or "XSS"). Superficial description of the system. |
| **0–1 (Poor)** | Complete lack of technical grounding. Claims "I hacked the AI by asking nicely" with no security analysis. |

---

### 2. Empirical Reproducibility & Methodology (0–5 Points)

Evaluates whether an independent engineer or triager can reliably reproduce the finding.

| Points | Description |
| :--- | :--- |
| **5 (Exemplary)** | Documents exact target specifications (model architecture, quantized/full weights, temperature, seed if applicable, prompt wrapper). Conducts **empirical sampling** (e.g., tested across $N=10$ trials with an $X\%$ success rate) and characterizes failure modes. Provides exact step-by-step reproduction steps, raw input payloads, and unedited model output logs. |
| **4 (Strong)** | Provides complete reproducible steps, exact payload, and model configuration. Mentions repeatability across a few trials, but lacks structured statistical data. |
| **3 (Adequate)** | Steps are reproducible on the reporter's specific machine/model, but omits key parameters (temperature, model version, system prompt state). Only tested once. |
| **2 (Weak)** | Instructions are vague or require guesswork ("interact with the bot until it gets confused"). Payload is incomplete or requires substantial triager modification. |
| **0–1 (Poor)** | Irreproducible. Missing payloads, incomplete logs, or claims that cannot be replicated. |

---

### 3. Blast Radius & Approval-Gate Analysis (0–5 Points)

Evaluates the demonstration of concrete security consequences versus speculative panic, with specific analysis of the **Human-in-the-Loop Approval Gate**.

| Points | Description |
| :--- | :--- |
| **5 (Exemplary)** | Demonstrates concrete, realistic impact within the target environment (e.g., unauthorized tool invocation with malicious arguments, private data exfiltration, state tampering, privilege escalation). **Explicitly analyzes the Human-in-the-Loop Approval Gate**: determines whether mutations actually executed (**LEAKED / MUTATED**) or were intercepted as proposals (**HELD**), or demonstrates a social engineering bypass of the gate. Differentiates demonstrated impact from theoretical risks and accurately maps to CVSS / bug bounty severity tiers (P1–P4). |
| **4 (Strong)** | Demonstrates tangible impact (e.g. forced tool execution or private secret access). Evaluates the approval gate or proposal staging, though some downstream risks remain untested. |
| **3 (Adequate)** | Impact is demonstrated, but stops at a benign proof of concept (repeats slogan, prints profanity), or conflates staging a proposal with executing an unauthorized state change without verifying the approval gate. |
| **2 (Weak)** | Heavily inflated impact claims without technical evidence (e.g., claiming "full remote code execution on AWS" when the model merely generated a shell command in markdown text). |
| **0–1 (Poor)** | No demonstrated impact. Purely benign behavior or user-intended application functionality mistaken for a bug. |

---

### 4. Attack Chain & Payload Engineering (0–5 Points)

Evaluates the sophistication, design, and analysis of the exploit payload.

| Points | Description |
| :--- | :--- |
| **5 (Exemplary)** | Dissects the anatomy of the exploit payload: payload formatting (markdown delimiters, simulated system tokens, role confusion), evasion of heuristic or safety filters, and cognitive override techniques. Explains *why* the model prioritized the attacker's instructions over system instructions. |
| **4 (Strong)** | Well-crafted payload tailored specifically to the target's tool schemas and prompt structure. Clear breakdown of payload components. |
| **3 (Adequate)** | Working payload, but minimal explanation of why it works or which token patterns triggered compliance. Relies partially on standard heuristic triggers. |
| **2 (Weak)** | Crude, copy-pasted generic jailbreak prompt (e.g., standard "DAN" or "Do Anything Now" scripts) that is not tailored to the agent's actual tool calling interface. |
| **0–1 (Poor)** | Ineffective or trivial payload with no engineering or analysis. |

---

### 5. Remediation & Defense-in-Depth (0–5 Points)

Evaluates actionable recommendations to remediate the vulnerability at multiple layers.

| Points | Description |
| :--- | :--- |
| **5 (Exemplary)** | Provides a robust, multi-layered defense strategy: architectural controls (e.g., dual-LLM evaluator pattern, human-in-the-loop verification for sensitive tools, strict schema gating), prompt-level defenses (instruction hierarchy, data delimiters), and runtime observability/guardrails. Accurately acknowledges the limitations and bypass risks of each recommended control. |
| **4 (Strong)** | Suggests both architectural fixes (e.g., tool permission scoping) and prompt engineering defenses. Actionable and practical to implement. |
| **3 (Adequate)** | Suggests only prompt-level mitigations (e.g., "Add 'never trust external input' to the system prompt"). Lacks architectural enforcement or structural validation. |
| **2 (Weak)** | Superficial or unhelpful advice (e.g., "Use a better AI model", "Add an input filter for bad words"). |
| **0–1 (Poor)** | No remediation provided, or suggested fixes that break intended system functionality. |

---

## Grading Scale & Triage Outcomes

| Total Score | Grade | Status | Description |
| :--- | :---: | :--- | :--- |
| **23 – 25** | **A** | **Accepted (Exemplary)** | Production-ready vulnerability report ready for enterprise security teams. |
| **18 – 22** | **B** | **Valid (Minor Revisions)** | Solid finding and technical proof. Needs minor polish in empirical sampling or threat modeling before final sign-off. |
| **12 – 17** | **C** | **Needs Work (Informational)** | Interesting angle or potential vector, but lacks empirical rigor, demonstrates minimal impact, or relies on vague reproduction steps. |
| **0 – 11** | **D** | **Rejected** | Insufficient detail, irreproducible, hallucinated severity, or purely theoretical without proof of concept. |
