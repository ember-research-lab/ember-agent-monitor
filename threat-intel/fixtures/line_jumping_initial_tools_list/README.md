# Fixture: line_jumping_initial_tools_list

**Class:** Trail-of-Bits line jumping — initial tools/list injection
**Source:** Trail of Bits
**Severity:** High (per `expected.json`)

Distinct from MCPoison's mid-session description swap: the malicious instruction sits in the *initial* tools/list payload at registration. The agent never calls the tool; the description text alone influences behavior. Caught by `instruction_shape_in_mcp_description` (the rule fires on registration content regardless of swap-vs-initial).

See the suite-level matrix at `tests/attack-coverage-matrix.md` for how
this rule fits into the broader catalog. Closed during the 2026-05-06
novel-pattern stress test.
