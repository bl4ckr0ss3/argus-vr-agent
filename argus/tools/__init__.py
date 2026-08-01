"""Tool registry for ARGUS.

Each tool exposes:
  - an Anthropic tool schema (name / description / input_schema)
  - a handler(input: dict) -> str

`build_tools()` wires the handlers to shared state (the BM25 index, config) and
returns both the schema list to hand to the Messages API and a name->handler
dispatch map for the agent loop.
"""
from __future__ import annotations

from typing import Callable

from ..rag import BM25Index
from .base import Tool
from . import filesystem, findings, knowledge, malware, shell, yara_tool
from . import http_request, kernel, network, llm_redteam, dynamic


def build_tools(index: BM25Index) -> tuple[list[dict], dict[str, Callable[[dict], str]]]:
    tools: list[Tool] = [
        knowledge.make_tool(index),
        filesystem.make_read_file(),
        filesystem.make_list_dir(),
        filesystem.make_grep(),
        shell.make_run_recon(),
        findings.make_record_candidate(),
        malware.make_unpack_sample(),
        malware.make_triage_report(),
        yara_tool.make_yara_scan(),
        http_request.make_http_request(),
        kernel.make_kernel_research(),
        network.make_network_recon(),
        llm_redteam.make_llm_redteam(),
        dynamic.make_dynamic_analysis(),
    ]
    schemas = [t.schema() for t in tools]
    dispatch = {t.name: t.handler for t in tools}
    return schemas, dispatch
