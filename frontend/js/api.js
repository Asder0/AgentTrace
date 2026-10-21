/**
 * API 模块 - 与后端 Flask 服务通信
 * 
 * 提供从后端获取图谱数据、事件历史、风险卡片等数据的接口。
 * 使用 agentdojo 原本的 AgentPipeline + FunctionsRuntime 执行真实工具调用。
 * 
 * 核心设计原则：
 * - 所有操作都通过后端 API 调用真实 LLM 和 FunctionsRuntime
 * - 前端不进行任何硬编码的指令解析或模拟
 * - 后端不可用时返回错误，不降级到模拟数据
 * 
 * 增强功能：
 * - 自定义指令执行（通过 /api/execute/custom）
 * - 预设场景执行（通过 /api/execute）
 * - LLM 配置管理（通过 /api/config/llm）
 * - 增量数据更新支持
 */

const API = {
    // 后端 API 基础 URL
    BASE_URL: 'http://localhost:5000/api',

    /**
     * 获取图谱数据
     * @returns {Promise<{graph: Object, summary: Object, events: Array}>}
     */
    async getGraphData() {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            const response = await fetch(`${this.BASE_URL}/graph`, {
                method: 'GET',
                headers: { 'Accept': 'application/json' },
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取图谱数据失败:', err.message);
            throw err;
        }
    },

    /**
     * 获取风险卡片列表
     * @returns {Promise<Array>}
     */
    async getRiskCards() {
        try {
            const response = await fetch(`${this.BASE_URL}/risk-cards`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取风险卡片失败:', err.message);
            throw err;
        }
    },

    /**
     * 获取事件历史
     * @returns {Promise<Array>}
     */
    async getEvents() {
        try {
            const response = await fetch(`${this.BASE_URL}/events`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取事件历史失败:', err.message);
            throw err;
        }
    },

    /**
     * 获取节点详情
     * @param {string} nodeId - 节点 ID
     * @returns {Promise<Object>}
     */
    async getNodeDetail(nodeId) {
        try {
            const response = await fetch(`${this.BASE_URL}/node/${encodeURIComponent(nodeId)}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取节点详情失败:', err.message);
            return null;
        }
    },

    /**
     * 获取所有可用的预设场景列表
     * @returns {Promise<Array>}
     */
    async getScenarios() {
        try {
            const response = await fetch(`${this.BASE_URL}/scenarios`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取场景列表失败:', err.message);
            throw err;
        }
    },

    /**
     * 执行预设场景操作（通过 AgentPipeline 调用真实 LLM 自主决策）
     * @param {string} action - 操作名称
     * @returns {Promise<Object>} 更新后的图谱数据
     */
    async executeAction(action) {
        try {
            const response = await fetch(`${this.BASE_URL}/execute`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action })
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('执行操作失败:', err.message);
            throw err;
        }
    },

    /**
     * 执行自定义指令（通过 AgentPipeline 调用真实 LLM 自主决策）
     * 用户输入自然语言指令，LLM 根据可用工具 API 自主决策工具调用
     * @param {Object} params - 自定义指令参数
     * @param {string} params.prompt - 自然语言指令（只发送原始指令，让 LLM 自主决策）
     * @returns {Promise<Object>} 更新后的图谱数据
     */
    async executeCustom(params) {
        try {
            const response = await fetch(`${this.BASE_URL}/execute/custom`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(params)
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('执行自定义指令失败:', err.message);
            throw err;
        }
    },

    /**
     * 重置所有数据
     * @returns {Promise<Object>}
     */
    async resetData() {
        try {
            const response = await fetch(`${this.BASE_URL}/reset`, {
                method: 'POST',
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('重置数据失败:', err.message);
            throw err;
        }
    },

    // ============================================================
    // 系统状态 API
    // ============================================================

    /**
     * 获取系统状态（健康检查 + 功能清单）
     * @returns {Promise<Object>} { status, layers, features, llm_config, graph_stats }
     */
    async getSystemStatus() {
        try {
            const response = await fetch(`${this.BASE_URL}/status`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取系统状态失败:', err.message);
            throw err;
        }
    },

    // ============================================================
    // LLM 配置 API
    // ============================================================

    /**
     * 获取当前 LLM 配置
     * @returns {Promise<Object>} { provider, model, has_api_key }
     */
    async getLLMConfig() {
        try {
            const response = await fetch(`${this.BASE_URL}/config/llm`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取 LLM 配置失败:', err.message);
            throw err;
        }
    },

    /**
     * 设置 LLM 配置
     * @param {Object} config - LLM 配置
     * @param {string} config.provider - 提供商 (google/openai/anthropic/local)
     * @param {string} config.model - 模型名称
     * @param {string} config.api_key - API Key
     * @returns {Promise<Object>}
     */
    async setLLMConfig(config) {
        try {
            const response = await fetch(`${this.BASE_URL}/config/llm`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('设置 LLM 配置失败:', err.message);
            throw err;
        }
    },

    // ============================================================
    // 防御配置 API
    // ============================================================

    /**
     * 获取当前防御机制状态
     * @returns {Promise<Object>} { enabled: boolean }
     */
    async getDefenseConfig() {
        try {
            const response = await fetch(`${this.BASE_URL}/config/defense`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取防御配置失败:', err.message);
            throw err;
        }
    },

    /**
     * 设置防御机制状态
     * @param {boolean} enabled - 是否启用防御机制
     * @returns {Promise<Object>} { enabled: boolean, status: string }
     */
    async getTraces() {
        try {
            const response = await fetch(`${this.BASE_URL}/traces`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) { return { traces: [], total: 0 }; }
    },

    async getTrace(traceId) {
        try {
            const r = await fetch(`${this.BASE_URL}/traces/${traceId}`);
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return await r.json();
        } catch (err) { return null; }
    },

    async setDefenseConfig(enabled, rings = null) {
        try {
            const body = {};
            if (enabled !== null && enabled !== undefined) {
                body.enabled = enabled;
            }
            if (rings) {
                body.rings = rings;
            }
            const response = await fetch(`${this.BASE_URL}/config/defense`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('设置防御配置失败:', err.message);
            throw err;
        }
    },

    // ============================================================
    // 攻击场景 API
    // ============================================================

    /**
     * 获取可用的攻击类型列表
     * @returns {Promise<Array>} [{ id, name, description }]
     */
    async getAttackTypes() {
        try {
            const response = await fetch(`${this.BASE_URL}/attack-types`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取攻击类型列表失败:', err.message);
            throw err;
        }
    },

    /**
     * 获取所有可用的 user_tasks（用于攻击场景选择器）
     * @returns {Promise<Array>} [{ id, suite, prompt, description, cross_app, cross_module }]
     */
    async getAttackUserTasks() {
        try {
            const response = await fetch(`${this.BASE_URL}/attack/user-tasks`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取攻击 user_tasks 失败:', err.message);
            throw err;
        }
    },

    /**
     * 获取所有可用的 injection_tasks（用于攻击场景选择器）
     * @returns {Promise<Array>} [{ id, suite, goal, description }]
     */
    async getAttackInjectionTasks() {
        try {
            const response = await fetch(`${this.BASE_URL}/attack/injection-tasks`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取攻击 injection_tasks 失败:', err.message);
            throw err;
        }
    },

    /**
     * 获取所有可用的攻击场景列表
     * @returns {Promise<Array>} [{ id, attack_type, attack_name, suite, user_task_id, injection_task_id, name, description }]
     */
    async getAttackScenarios() {
        try {
            const response = await fetch(`${this.BASE_URL}/attack-scenarios`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取攻击场景列表失败:', err.message);
            throw err;
        }
    },

    /**
     * 执行攻击场景
     * @param {Object} params - 攻击场景参数
     * @param {string} params.user_task_id - 用户任务 ID
     * @param {string} params.injection_task_id - 注入任务 ID
     * @param {string} params.attack_type - 攻击类型
     * @param {string} params.suite - 套件名称
     * @returns {Promise<Object>} 执行结果（含图谱数据、风险卡片等）
     */
    async executeAttack(params) {
        try {
            const response = await fetch(`${this.BASE_URL}/execute/attack`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(params)
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('执行攻击场景失败:', err.message);
            throw err;
        }
    },

    // ============================================================
    // 存储视图 API
    // ============================================================

    /**
     * 获取四个 suite 的存储概要
     * @returns {Promise<Object>} { suites: [...] }
     */
    async getStorageSuites() {
        try {
            const response = await fetch(`${this.BASE_URL}/storage/suites`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取存储概要失败:', err.message);
            throw err;
        }
    },

    /**
     * 获取指定 suite 的初始/当前快照与差异
     * @param {string} suite
     * @param {string} include - both | initial | current
     * @returns {Promise<Object>}
     */
    async getStorageSuite(suite, include = 'both') {
        try {
            const url = `${this.BASE_URL}/storage/suites/${encodeURIComponent(suite)}?include=${encodeURIComponent(include)}`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (err) {
            console.error('获取存储快照失败:', err.message);
            throw err;
        }
    },
};
