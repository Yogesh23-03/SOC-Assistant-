# SOC benchmark
Mode: offline
Model: scripted-fixture (not model evaluation)
Alerts: 10
Measured model accuracy: None
False-positive auto-close rate: None
Unsafe auto-closes: None
Median alert-to-proposal seconds: 0.002
Execution claims in model outputs: 0

Pipeline outputs only; does not measure real firewall actions or browser latency

Offline labels are scripted. Do not present offline results as model accuracy.

| Case | Expected | Predicted | Action | Seconds |
|---|---|---|---|---|
| A-001 | true_attack | true_attack | escalate | 0.0067 |
| A-002 | false_positive | false_positive | none | 0.0007 |
| A-003 | suspicious | suspicious | escalate | 0.0018 |
| A-004 | true_attack | true_attack | escalate | 0.0074 |
| A-005 | false_positive | false_positive | none | 0.0007 |
| A-006 | true_attack | true_attack | escalate | 0.002 |
| A-007 | suspicious | suspicious | escalate | 0.0049 |
| A-008 | true_attack | true_attack | escalate | 0.0011 |
| A-009 | false_positive | false_positive | none | 0.0004 |
| A-010 | true_attack | true_attack | escalate | 0.0014 |
