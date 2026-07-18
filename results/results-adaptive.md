| Defense | Attack success % | Clean task completion % | Utility under attack % |
|---|---|---|---|
| none | 62.0 | 100.0 | 98.0 |
| allowlist | 4.0 | 100.0 | 100.0 |
| judge | 0.0 | 100.0 | 52.0 |
| taintgate | 0.0 | 58.3 | 50.0 |
| taintgate-flow | 8.0 | 91.7 | 90.0 |

**Limits.** Small custom benchmark (12 tasks, 5 attack goals), mock tools, one agent model, a cheap black-box attacker with a few rounds. `ask` decisions count as `deny`. The allowlist baseline knows each task's tools and recipients in advance, which a real deployment would not. Numbers show the shape of the tradeoff, not a security guarantee, and are not comparable to AgentDojo results.
