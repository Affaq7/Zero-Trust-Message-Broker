"""Force third-party telemetry and tracing off (CrewAI, OpenTelemetry,
LangChain/LangSmith, ChromaDB). Values are overwritten, not defaulted, so a
stray setting cannot turn them back on. Call before importing the frameworks.
"""

import os
from collections.abc import MutableMapping

OFF = {
    "CREWAI_DISABLE_TELEMETRY": "true",
    "CREWAI_DISABLE_TRACKING": "true",
    "CREWAI_TRACING_ENABLED": "false",
    "OTEL_SDK_DISABLED": "true",
    "LANGCHAIN_TRACING_V2": "false",
    "LANGCHAIN_TRACING": "false",
    "LANGSMITH_TRACING": "false",
    "ANONYMIZED_TELEMETRY": "False",   # ChromaDB (pulled in by CrewAI)
}


def disable_telemetry(environ: MutableMapping[str, str] = os.environ) -> None:
    environ.update(OFF)
