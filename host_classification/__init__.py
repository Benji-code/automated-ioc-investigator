"""Host classification: what kind of machine a campus host is, and what is
normal for that kind of machine.

  features.py   per-host behaviour features from SuperNetFlow (one host or the campus)
  classify.py   random forest from verified seeds, plus transparent rules
  profiles.py   per-type behaviour profiles, and one host compared with its type
  __main__.py   the command line: python -m host_classification --help

The agent (agent/host_type.py) classifies each case's host and compares it
with its type; the report's analysis uses that comparison.
"""
