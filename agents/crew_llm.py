"""Run one CrewAI task on our LLM layer (agents/llm.py).

CrewAI builds the prompt (role, goal, backstory, task, output schema) and
calls CrewLLM once; CrewLLM hands it to LLMClient.decide(), so the context
window guard, the JSON schema, the retry, the call log and the fake backend
all apply. Telemetry is switched off before CrewAI is imported.
"""

from typing import Any, TypeVar

from pydantic import BaseModel, Field

from agents.telemetry import disable_telemetry

disable_telemetry()

from crewai import Agent, Crew, Task  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402

from agents.llm import LLMClient, LLMOutputError  # noqa: E402

T = TypeVar("T", bound=BaseModel)


class CrewLLM(BaseLLM):
    llm_client: Any = Field(exclude=True)
    purpose: str

    def call(self, messages, tools=None, callbacks=None, available_functions=None,
             from_task=None, from_agent=None, response_model=None):
        if response_model is None:
            raise ValueError("CrewLLM needs a task with output_pydantic")
        if isinstance(messages, str):
            messages = [{"role": "user", "content": messages}]
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        prompt = "\n\n".join(m["content"] for m in messages if m["role"] != "system")
        decision = self.llm_client.decide(purpose=self.purpose, system=system,
                                          prompt=prompt, schema=response_model)
        return decision.model_dump_json()

    def supports_function_calling(self) -> bool:
        return False


def _escape(text: str) -> str:
    # CrewAI fills {placeholders} in descriptions; keep literal braces literal.
    return text.replace("{", "{{").replace("}", "}}")


def run_crew_task(llm: LLMClient, *, purpose: str, role: str, goal: str, backstory: str,
                  description: str, expected_output: str, schema: type[T]) -> T:
    crew_llm = CrewLLM(model=llm.settings.model, llm_client=llm, purpose=purpose, temperature=0.0)
    agent = Agent(role=role, goal=goal, backstory=backstory, llm=crew_llm,
                  verbose=False, allow_delegation=False, max_iter=1, max_retry_limit=0)
    task = Task(description=_escape(description), expected_output=_escape(expected_output),
                agent=agent, output_pydantic=schema)
    out = Crew(agents=[agent], tasks=[task], verbose=False).kickoff()
    if not isinstance(out.pydantic, schema):
        raise LLMOutputError(f"{purpose}: CrewAI returned no {schema.__name__}")
    return out.pydantic
