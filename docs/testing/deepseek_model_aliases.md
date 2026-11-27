# DeepSeek 模型名称与思考模式

本文记录 2026-11-19 对 DeepSeek API 实际行为的核实结果。它用于避免批量
验证和视频演示把历史模型别名与当前模型名称混为一谈。

## 结论

- 当前官方模型列表中只列出 `deepseek-flash` 和 `deepseek-v4-pro`。
- `deepseek-chat` 已从公开模型列表移除，但服务端仍接受该名称作为兼容别名。
- 用 `deepseek-chat` 发起请求时，响应中的 `model` 字段会规范化为
  `deepseek-flash`。
- 未显式设置思考参数时，`deepseek-chat` 不返回 `reasoning_content`；
  `deepseek-flash` 会进入思考模式并返回 `reasoning_content`。
- 因此，截至核实日期，`deepseek-chat` 的实际行为是
  **DeepSeek-V4.1-Flash-1017 的非思考兼容模式**。

`deepseek-chat` 不是当前官方稳定模型标识，也不是旧版
`deepseek-v4-flash` 模型本身。官方曾将历史 `deepseek-chat` 定义为
V4-Flash 的非思考模式，但该映射原计划在 2026-07-24 停用。当前仍可调用
属于未写入现行模型列表的兼容行为，不应作为长期 API 契约。

## 建议

批量验证应在报告中明确记录实际请求名称和模型路由。需要长期稳定的非思考
配置时，优先请求当前的 `deepseek-flash`，并显式关闭思考模式：

```json
{
  "model": "deepseek-flash",
  "thinking": {
    "type": "disabled"
  }
}
```

如果实验继续使用 `deepseek-chat`，报告应写成“当前兼容别名，实际路由到
DeepSeek-V4.1-Flash 非思考模式”，不能只写“DeepSeek V4 Flash”，也不能把
实验结果描述为旧版 `deepseek-v4-flash` 的结果。

## 依据

- [DeepSeek Models & Pricing](https://api-docs.deepseek.com/quick_start/pricing)
- [DeepSeek Thinking Mode](https://api-docs.deepseek.com/guides/thinking_mode)
- [DeepSeek Change Log](https://api-docs.deepseek.com/updates)
- 2026-11-19 使用真实 API Key 对照调用：
  - `deepseek-chat` 的响应模型为 `deepseek-flash`，未返回
    `reasoning_content`；
  - `deepseek-flash` 的响应模型为 `deepseek-flash`，未显式关闭思考时返回
    `reasoning_content`。
