"""DeepSeek LLM pipeline element.

DeepSeek API is compatible with OpenAI's API format, but does NOT support
the `developer` role (OpenAI's new feature). It only supports:
`system`, `user`, `assistant`, `tool`.

This module provides a custom LLM class that converts `developer` role
messages back to `system` role before sending to DeepSeek API.
"""

from collections.abc import Sequence

import openai
from openai.types.chat import (
    ChatCompletionAssistantMessageParam,
    ChatCompletionContentPartTextParam,
    ChatCompletionDeveloperMessageParam,
    ChatCompletionMessageParam,
    ChatCompletionSystemMessageParam,
    ChatCompletionToolMessageParam,
    ChatCompletionUserMessageParam,
)

from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM, _function_to_openai, _message_to_openai, _openai_to_assistant_message, chat_completion_request
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage


def _message_to_deepseek(message: ChatMessage, model_name: str) -> ChatCompletionMessageParam:
    """Convert a ChatMessage to DeepSeek API format.
    
    DeepSeek does NOT support the `developer` role (OpenAI's new feature).
    This function converts `developer` role back to `system` role.
    """
    match message["role"]:
        case "system":
            # DeepSeek uses "system" role, not "developer"
            return ChatCompletionSystemMessageParam(
                role="system", content=_content_blocks_to_openai_content_blocks(message)
            )
        case "user":
            return ChatCompletionUserMessageParam(
                role="user", content=_content_blocks_to_openai_content_blocks(message)
            )
        case "assistant":
            from openai.types.chat import ChatCompletionMessageToolCallParam
            if message["tool_calls"] is not None and len(message["tool_calls"]) > 0:
                from agentdojo.agent_pipeline.llms.openai_llm import _tool_call_to_openai
                tool_calls = [_tool_call_to_openai(tool_call) for tool_call in message["tool_calls"]]
                return ChatCompletionAssistantMessageParam(
                    role="assistant",
                    content=_content_blocks_to_openai_content_blocks(message),
                    tool_calls=tool_calls,
                )
            return ChatCompletionAssistantMessageParam(
                role="assistant",
                content=_content_blocks_to_openai_content_blocks(message),
            )
        case "tool":
            if message["tool_call_id"] is None:
                raise ValueError("`tool_call_id` should be specified for DeepSeek.")
            return ChatCompletionToolMessageParam(
                content=message["error"] or _content_blocks_to_openai_content_blocks(message),
                tool_call_id=message["tool_call_id"],
                role="tool",
                name=message["tool_call"].function,
            )
        case _:
            raise ValueError(f"Invalid message type: {message}")


def _content_blocks_to_openai_content_blocks(
    message: ChatMessage,
) -> list[ChatCompletionContentPartTextParam] | None:
    if message["content"] is None:
        return None
    return [ChatCompletionContentPartTextParam(type="text", text=el["content"] or "") for el in message["content"]]


class DeepSeekLLM(OpenAILLM):
    """LLM pipeline element for DeepSeek API.
    
    DeepSeek API is compatible with OpenAI's API format, but does NOT support
    the `developer` role. This class overrides the query method to use
    `system` role instead of `developer` role.
    """

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        # Use DeepSeek-compatible message conversion (system role, not developer)
        deepseek_messages = [_message_to_deepseek(message, self.model) for message in messages]
        openai_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        completion = chat_completion_request(
            self.client, self.model, deepseek_messages, openai_tools, self.reasoning_effort, self.temperature
        )
        output = _openai_to_assistant_message(completion.choices[0].message)
        messages = [*messages, output]
        return query, runtime, env, messages, extra_args
