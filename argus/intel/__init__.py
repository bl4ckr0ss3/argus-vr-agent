"""Autonomous malware-intel pipeline: collect -> static triage -> vault + dashboard.

Collection sources drop files into config.INTAKE_DIR; the watcher triages each
new sample statically (no execution). Run this inside an isolated analysis VM.
"""
