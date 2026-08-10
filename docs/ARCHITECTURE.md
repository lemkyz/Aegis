# Aegis Public Architecture

The public boundary is deliberately small.

```text
Developer / software agent
        |
        v
VS Code / CLI / CI
        |
        v
Local Aegis Runtime
        |
        +--> claim + evidence
        +--> authorization
        +--> remediation
        +--> independent verification
        +--> policy
        +--> security memory
```

Aegis keeps these concepts distinct:

- a finding is not proof;
- analysis is not authorization;
- a patch is not verification;
- model agreement is not policy;
- failed execution is not evidence of safety;
- remembered state must stay bound to valid provenance.

The proprietary implementation behind this public contract is not published in this repository.
