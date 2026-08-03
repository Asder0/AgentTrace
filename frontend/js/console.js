/**
 * 控制台模块 - 操作控制台
 * 
 * 提供预设任务执行和自定义指令输入功能。
 * 所有操作通过 API 模块发送到后端，由 AgentPipeline 调用真实 LLM 自主决策。
 * 
 * 核心设计原则：
 * - 用户指令直接发送给后端，不经过任何前端硬编码解析
 * - 后端 AgentPipeline 让 LLM 根据可用工具 API 自主决策工具调用
 * - 可视化层只负责展示真实的调用流和数据流
 * 
 * 增强功能：
 * - LLM 配置面板（提供商、模型、API Key）
 * - 预设任务按钮（从后端动态加载）
 * - 自定义指令输入（支持自然语言）
 * - 执行状态反馈
 */

const CONSOLE = {
    /** 当前是否正在执行操作 */
    _isExecuting: false,
    
    /** 当前 LLM 配置 */
    _llmConfig: {
        provider: 'deepseek',
        model: 'deepseek-v4-flash',
        api_key: '',
    },

    /**
     * 初始化控制台
     */
    async init() {
        this._bindEvents();
        await this.loadScenarios();
        await this._loadLLMConfig();
        this._renderLLMConfigPanel();
        await this._initDefenseToggle();
        await this._loadAttackScenarios();
    },

    /**
     * 绑定事件
     */
    _bindEvents() {
        // 自定义指令执行按钮
        const btnCustom = document.getElementById('btnCustomAction');
        const inputCustom = document.getElementById('inputCustomAction');
        
        if (btnCustom) {
            btnCustom.addEventListener('click', () => this._handleCustomAction());
        }
        
        if (inputCustom) {
            inputCustom.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    this._handleCustomAction();
                }
            });
        }
    },

    /**
     * 加载预设场景列表
     */
    async loadScenarios() {
        const container = document.getElementById('scenarioButtons');
        if (!container) return;
        
        try {
            const scenarios = await API.getScenarios();
            
            if (!scenarios || scenarios.length === 0) {
                container.innerHTML = '<p class="hint">暂无可用场景</p>';
                return;
            }
            
            container.innerHTML = '';
            
            scenarios.forEach(scenario => {
                const btn = document.createElement('button');
                btn.className = 'scenario-btn';
                if (scenario.is_risk) {
                    btn.classList.add('risk');
                }
                if (scenario.is_sensitive) {
                    btn.classList.add('sensitive');
                }
                if (scenario.cross_app) {
                    btn.classList.add('cross-app');
                }
                
                btn.dataset.action = scenario.id;
                btn.title = scenario.description;
                
                // 添加标签
                let badges = '';
                if (scenario.is_risk) badges += '<span class="badge badge-risk">风险</span>';
                if (scenario.is_sensitive) badges += '<span class="badge badge-sensitive">敏感</span>';
                if (scenario.cross_app) badges += '<span class="badge badge-cross">跨APP</span>';
                
                btn.innerHTML = `${scenario.name} ${badges}`;
                
                btn.addEventListener('click', () => this._executeScenario(scenario.id));
                
                container.appendChild(btn);
            });
            
        } catch (err) {
            console.error('加载场景列表失败:', err);
            container.innerHTML = '<p class="hint">加载场景失败，请检查后端服务</p>';
        }
    },

    /**
     * 执行预设场景
     * 预设场景只发送 prompt 文本给后端，由 AgentPipeline 让 LLM 自主决策
     */
    async _executeScenario(action) {
        if (this._isExecuting) return;
        
        this._isExecuting = true;
        this._showFeedback('⏳ 正在通过 AgentPipeline 执行操作（LLM 自主决策）...', 'info');
        
        // 发布场景执行事件（触发追踪面板）
        Store.publish('scenario_executed', { action });
        
        try {
            const result = await API.executeAction(action);

            
            if (result.error) {
                this._showFeedback(`❌ ${result.error}`, 'error');
                return;
            }
            
            // 更新图谱 - 优先使用返回的 graph 数据，否则强制从后端重新加载
            if (result.graph && result.graph.nodes && result.graph.nodes.length > 0) {
                GRAPH.setData(result.graph.nodes, result.graph.links);
                GRAPH.render();
                const riskCardCount = result.risk_cards?.length || 0;
                GRAPH.updateStats(result.summary, riskCardCount);
            } else {
                // 后端可能没有返回 graph 数据，强制重新加载
                await GRAPH.loadData();
            }
            
            // 更新事件时间线
            if (result.events) {
                TIMELINE.loadEvents(result.events);
            } else {
                // 强制刷新事件
                try {
                    const events = await API.getEvents();
                    if (events) TIMELINE.loadEvents(events);
                } catch(e) {}
            }
            
            // 更新风险卡片
            if (result.risk_cards) {
                RISK_PANEL.loadRiskCards();
            } else {
                RISK_PANEL.loadRiskCards();
            }
            
            // 从执行结果中直接渲染追踪面板
            // 注意：后端 _build_trace_steps_from_messages 已包含阻断步骤，前端不再重复添加
            if (result.steps && result.steps.length > 0) {
                TRACE_PANEL._renderTrace({
                    trace_id: result.trace_id || action,
                    command: action,
                    llm_mode: 'real',
                    steps: result.steps,
                    total_steps: result.steps.length,
                });
            }
            
            // 显示执行结果
            const llmMode = 'real';
            const modeText = '真实 LLM';
            
            if (result.blocked) {
                const riskCount = result.risk_cards?.length || 0;
                const reasons = result.risk_cards?.map(c => c.detail).join('; ') || '';
                this._showFeedback(`🚫 操作已被阻断！(${riskCount} 个风险卡片) ${reasons ? '原因: ' + reasons.substring(0, 100) : ''}`, 'error');
            } else {
                this._showFeedback(`✅ 操作执行成功 (${modeText})`, 'success');
            }
            
            // 更新统计
            const nodeCount = result.graph?.nodes?.length || 0;
            const edgeCount = result.graph?.links?.length || 0;
            if (nodeCount > 0) {
                Store.set('lastNodeCount', nodeCount);
                Store.set('lastEdgeCount', edgeCount);
            }
            
        } catch (err) {
            console.error('执行场景失败:', err);
            this._showFeedback(`❌ 执行失败: ${err.message}`, 'error');
        } finally {
            this._isExecuting = false;
        }
    },

    /**
     * 处理自定义指令
     * 直接将原始指令发送给后端，不进行任何前端硬编码解析
     * 由后端的 AgentPipeline 调用真实 LLM 自主决策工具调用
     */
    async _handleCustomAction() {
        if (this._isExecuting) return;
        
        const input = document.getElementById('inputCustomAction');
        if (!input) return;
        
        const text = input.value.trim();
        if (!text) {
            this._showFeedback('⚠️ 请输入指令内容', 'warning');
            return;
        }
        
        this._isExecuting = true;
        this._showFeedback('⏳ 正在通过 AgentPipeline 解析并执行自定义指令（LLM 自主决策）...', 'info');
        
        try {
            // 直接将原始指令发送给后端，不进行任何前端解析
            // 由后端的 AgentPipeline（真实 LLM）自主决策工具调用
            const params = {
                prompt: text,  // 只发送原始指令，让 LLM 自主决策
            };
            
            const result = await API.executeCustom(params);

            
            if (result.error) {
                this._showFeedback(`❌ ${result.error}`, 'error');
                return;
            }
            
            // 更新图谱 - 优先使用返回的 graph 数据，否则强制从后端重新加载
            if (result.graph && result.graph.nodes && result.graph.nodes.length > 0) {
                GRAPH.setData(result.graph.nodes, result.graph.links);
                GRAPH.render();
                const riskCardCount = result.risk_cards?.length || 0;
                GRAPH.updateStats(result.summary, riskCardCount);
            } else {
                // 后端可能没有返回 graph 数据，强制重新加载
                await GRAPH.loadData();
            }
            
            // 更新事件时间线
            if (result.events) {
                TIMELINE.loadEvents(result.events);
            } else {
                // 强制刷新事件
                try {
                    const events = await API.getEvents();
                    if (events) TIMELINE.loadEvents(events);
                } catch(e) {}
            }
            
            // 更新风险卡片
            RISK_PANEL.loadRiskCards();
            
            // 发布自定义指令事件（触发追踪面板）
            Store.publish('custom_command', { command: text });
            
            // 从执行结果中直接渲染追踪面板（不依赖独立的追踪 API）
            // 注意：后端 _build_trace_steps_from_messages 已包含阻断步骤，前端不再重复添加
            if (result.steps && result.steps.length > 0) {
                TRACE_PANEL._renderTrace({
                    trace_id: result.trace_id || 'custom',
                    command: text,
                    llm_mode: 'real',
                    steps: result.steps,
                    total_steps: result.steps.length,
                });
            }
            
            const llmMode = 'real';
            const modeText = '真实 LLM';
            
            if (result.blocked) {
                const riskCount = result.risk_cards?.length || 0;
                const reasons = result.risk_cards?.map(c => c.detail).join('; ') || '';
                this._showFeedback(`🚫 操作已被阻断！(${riskCount} 个风险卡片) ${reasons ? '原因: ' + reasons.substring(0, 100) : ''}`, 'error');
            } else {
                this._showFeedback(`✅ 自定义指令执行成功 (${modeText})`, 'success');
            }
            
            // 清空输入框
            input.value = '';
            
            // 更新统计
            const nodeCount = result.graph?.nodes?.length || 0;
            const edgeCount = result.graph?.links?.length || 0;
            if (nodeCount > 0) {
                Store.set('lastNodeCount', nodeCount);
                Store.set('lastEdgeCount', edgeCount);
            }
            
        } catch (err) {

            console.error('执行自定义指令失败:', err);
            this._showFeedback(`❌ 执行失败: ${err.message}`, 'error');
        } finally {
            this._isExecuting = false;
        }
    },

    /**
     * 显示反馈信息
     */
    _showFeedback(message, type = 'info') {
        const feedback = document.getElementById('consoleFeedback');
        if (!feedback) return;
        
        const typeStyles = {
            'info': { bg: 'var(--accent-blue)', icon: 'ℹ️' },
            'success': { bg: 'var(--accent-green)', icon: '✅' },
            'error': { bg: 'var(--accent-red)', icon: '❌' },
            'warning': { bg: 'var(--accent-yellow)', icon: '⚠️' },
        };
        
        const style = typeStyles[type] || typeStyles.info;
        
        feedback.textContent = message;
        feedback.style.display = 'block';
        feedback.style.borderLeftColor = style.bg;
        feedback.style.background = `${style.bg}15`;
        
        // 自动隐藏（错误和警告保留更长时间）
        const duration = type === 'error' ? 8000 : type === 'warning' ? 6000 : 4000;
        clearTimeout(this._feedbackTimer);
        this._feedbackTimer = setTimeout(() => {
            feedback.style.display = 'none';
        }, duration);
    },

    // ============================================================
    // LLM 配置管理
    // ============================================================

    /**
     * 加载 LLM 配置
     */
    async _loadLLMConfig() {
        try {
            const config = await API.getLLMConfig();
            this._llmConfig = {
                ...this._llmConfig,
                ...config,
                api_key: '',  // 不从前端获取已有 key
            };
        } catch (err) {
            console.warn('加载 LLM 配置失败:', err);
        }
    },

    /**
     * 渲染 LLM 配置面板
     * 始终使用真实 LLM 模式，没有"模拟模式"开关
     */
    _renderLLMConfigPanel() {
        const consoleCard = document.querySelector('.console-card');
        if (!consoleCard) return;
        
        // 创建 LLM 配置区域
        const llmSection = document.createElement('div');
        llmSection.className = 'console-section llm-config-section';
        
        const hasApiKey = this._llmConfig.has_api_key || false;
        
        llmSection.innerHTML = `
            <div class="console-label llm-config-header">
                🤖 LLM 配置
                <span class="llm-status" id="llmStatus">${hasApiKey ? '🟢 已配置' : '🔴 未配置'}</span>
            </div>
            <div class="llm-config-grid">
                <div class="llm-config-row">
                    <label class="llm-config-label">提供商</label>
                    <select id="llmProvider" class="llm-config-select">
                        <option value="deepseek" ${this._llmConfig.provider === 'deepseek' ? 'selected' : ''}>DeepSeek</option>
                        <option value="google" ${this._llmConfig.provider === 'google' ? 'selected' : ''}>Google Gemini</option>
                        <option value="openai" ${this._llmConfig.provider === 'openai' ? 'selected' : ''}>OpenAI</option>
                        <option value="anthropic" ${this._llmConfig.provider === 'anthropic' ? 'selected' : ''}>Anthropic Claude</option>
                        <option value="local" ${this._llmConfig.provider === 'local' ? 'selected' : ''}>Local LLM</option>
                    </select>
                </div>
                <div class="llm-config-row">
                    <label class="llm-config-label">模型</label>
                    <input type="text" id="llmModel" class="llm-config-input" 
                           value="${this._llmConfig.model}" 
                           placeholder="如: gemini-2.0-flash-001">
                </div>
                <div class="llm-config-row">
                    <label class="llm-config-label">API Key</label>
                    <input type="password" id="llmApiKey" class="llm-config-input" 
                           placeholder="输入 API Key">
                </div>
                <div class="llm-config-row llm-config-actions">
                    <button id="btnSaveLLMConfig" class="btn-execute llm-save-btn">💾 保存配置</button>
                </div>
                <div class="llm-config-row">
                    <p class="llm-config-hint">
                        ${hasApiKey 
                            ? '✅ 真实 LLM 已配置，操作将通过 AgentPipeline 调用大模型 API 自主决策'
                            : '💡 请配置 API Key 以启用真实 LLM。用户指令将直接输入给大模型，大模型根据可用工具 API 自主决策工具调用'}
                    </p>
                </div>
            </div>
            <!-- 防御机制开关 -->
            <div class="console-label llm-config-header" style="margin-top: 12px; border-top: 1px solid var(--border-color); padding-top: 12px;">
                🛡️ 防御机制
                <span class="defense-status" id="defenseStatusText">加载中...</span>
            </div>
            <div class="llm-config-grid">
                <div class="llm-config-row">
                    <label class="llm-config-label">Analysis Pipeline</label>
                    <label class="toggle-switch">
                        <input type="checkbox" id="defenseToggle" checked>
                        <span class="toggle-slider"></span>
                    </label>
                    <span style="font-size: 12px; color: var(--text-secondary); margin-left: 8px;">
                        关闭后跳过 Ring 1-4 检测
                    </span>
                </div>
            </div>
        `;
        
        // 在自定义指令区域之前插入
        const customSection = consoleCard.querySelector('.console-section:has(.custom-input-group)');
        if (customSection) {
            consoleCard.insertBefore(llmSection, customSection);
        } else {
            // 在预设任务区域之后插入
            const scenarioSection = consoleCard.querySelector('.console-section:first-child');
            if (scenarioSection) {
                scenarioSection.after(llmSection);
            } else {
                consoleCard.appendChild(llmSection);
            }
        }
        
        // 绑定 LLM 配置保存事件
        this._bindLLMConfigEvents();
    },

    /**
     * 绑定 LLM 配置事件
     */
    _bindLLMConfigEvents() {
        const saveBtn = document.getElementById('btnSaveLLMConfig');
        if (!saveBtn) return;
        
        saveBtn.addEventListener('click', async () => {
            await this._saveLLMConfig();
        });
        
        // 回车键保存
        const apiKeyInput = document.getElementById('llmApiKey');
        if (apiKeyInput) {
            apiKeyInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    this._saveLLMConfig();
                }
            });
        }
        
        // 防御开关切换事件
        const defenseToggle = document.getElementById('defenseToggle');
        if (defenseToggle) {
            defenseToggle.addEventListener('change', () => {
                this._toggleDefense();
            });
        }
    },

    /**
     * 保存 LLM 配置
     */
    async _saveLLMConfig() {
        const provider = document.getElementById('llmProvider')?.value || 'deepseek';
        const model = document.getElementById('llmModel')?.value || 'deepseek-v4-flash';
        const apiKey = document.getElementById('llmApiKey')?.value || '';
        
        if (!apiKey) {
            this._showFeedback('⚠️ 需要提供 API Key', 'warning');
            return;
        }
        
        const config = { provider, model, api_key: apiKey };
        
        try {
            const result = await API.setLLMConfig(config);
            
            if (result.status === 'ok') {
                this._llmConfig = { ...this._llmConfig, ...config, api_key: apiKey ? '***' : '' };
                
                // 更新状态指示器
                const statusEl = document.getElementById('llmStatus');
                if (statusEl) {
                    statusEl.textContent = '🟢 已配置';
                }
                
                // 清空 API Key 输入框（安全）
                const apiKeyInput = document.getElementById('llmApiKey');
                if (apiKeyInput) {
                    apiKeyInput.value = '';
                }
                
                this._showFeedback(
                    `✅ LLM 配置已保存，已启用 ${provider}/${model}`,
                    'success'
                );
            } else {
                this._showFeedback('❌ 保存 LLM 配置失败', 'error');
            }
        } catch (err) {
            console.error('保存 LLM 配置失败:', err);
            this._showFeedback(`❌ 保存失败: ${err.message}`, 'error');
        }
    },

    // ============================================================
    // 防御机制开关
    // ============================================================

    /**
     * 初始化防御开关状态
     */
    async _initDefenseToggle() {
        try {
            const config = await API.getDefenseConfig();
            const toggle = document.getElementById('defenseToggle');
            const statusText = document.getElementById('defenseStatusText');
            if (toggle) {
                toggle.checked = config.enabled;
            }
            if (statusText) {
                statusText.textContent = config.enabled ? '🟢 已启用' : '🔴 已关闭';
                statusText.className = config.enabled ? 'defense-status enabled' : 'defense-status disabled';
            }
        } catch (err) {
            console.warn('获取防御配置失败:', err.message);
        }
    },

    /**
     * 切换防御机制状态
     */
    async _toggleDefense() {
        const toggle = document.getElementById('defenseToggle');
        if (!toggle) return;
        
        const enabled = toggle.checked;
        const statusText = document.getElementById('defenseStatusText');
        
        try {
            const result = await API.setDefenseConfig(enabled);
            if (result.status === 'ok') {
                if (statusText) {
                    statusText.textContent = enabled ? '🟢 已启用' : '🔴 已关闭';
                    statusText.className = enabled ? 'defense-status enabled' : 'defense-status disabled';
                }
                this._showFeedback(
                    enabled ? '🛡️ 防御机制已启用' : '🛡️ 防御机制已关闭',
                    'info'
                );
            }
        } catch (err) {
            console.error('设置防御配置失败:', err);
            // 恢复开关状态
            toggle.checked = !enabled;
            this._showFeedback(`❌ 设置防御配置失败: ${err.message}`, 'error');
        }
    },

    // ============================================================
    // 攻击场景
    // ============================================================

    /** 缓存 user_tasks 和 injection_tasks 列表 */
    _attackUserTasks: [],
    _attackInjectionTasks: [],

    /**
     * 加载攻击场景列表
     * 改为"选择器 + 快速预设"模式：
     * 1. 上方显示选择器（攻击类型、user_task、injection_task、suite）
     * 2. 下方显示快速预设按钮（常用组合）
     */
    async _loadAttackScenarios() {
        const container = document.getElementById('attackScenarioButtons');
        if (!container) return;
        
        try {
            // 并行加载所有数据
            const [scenarios, userTasks, injTasks, attackTypes] = await Promise.all([
                API.getAttackScenarios(),
                API.getAttackUserTasks(),
                API.getAttackInjectionTasks(),
                API.getAttackTypes(),
            ]);
            
            this._attackUserTasks = userTasks || [];
            this._attackInjectionTasks = injTasks || [];
            
            if (!scenarios || scenarios.length === 0) {
                container.innerHTML = '<p class="hint">暂无攻击场景</p>';
                return;
            }
            
            container.innerHTML = '';
            
            // ============================================================
            // 第一部分：选择器（自定义组合）
            // ============================================================
            const selectorSection = document.createElement('div');
            selectorSection.className = 'attack-selector-section';
            selectorSection.innerHTML = `
                <div class="attack-selector-title">🎛️ 自定义攻击组合</div>
                <div class="attack-selector-grid">
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">套件</label>
                        <select id="attackSuiteSelect" class="attack-selector-select">
                            <option value="workspace">📋 Workspace</option>
                            <option value="banking">🏦 Banking</option>
                        </select>
                    </div>
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">攻击类型</label>
                        <select id="attackTypeSelect" class="attack-selector-select">
                            ${attackTypes.map(at => `<option value="${at.id}">${at.icon} ${at.name}</option>`).join('')}
                        </select>
                    </div>
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">用户任务</label>
                        <select id="attackUserTaskSelect" class="attack-selector-select">
                            <option value="">-- 选择用户任务 --</option>
                        </select>
                    </div>
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">注入任务</label>
                        <select id="attackInjectionTaskSelect" class="attack-selector-select">
                            <option value="">-- 选择注入任务 --</option>
                        </select>
                    </div>
                    <div class="attack-selector-row attack-selector-actions">
                        <button id="btnExecuteCustomAttack" class="btn-execute attack-execute-btn">🚀 执行自定义攻击</button>
                        <span class="attack-selector-hint">选择参数后点击执行</span>
                    </div>
                </div>
            `;
            container.appendChild(selectorSection);
            
            // 填充选择器选项
            this._populateAttackSelectors();
            
            // 绑定选择器事件
            this._bindAttackSelectorEvents();
            
            // ============================================================
            // 第二部分：快速预设（常用组合）
            // ============================================================
            const presetSection = document.createElement('div');
            presetSection.className = 'attack-preset-section';
            presetSection.innerHTML = `
                <div class="attack-preset-title">⚡ 快速预设</div>
            `;
            
            // 按攻击类型分组
            const grouped = {};
            scenarios.forEach(s => {
                if (!grouped[s.attack_type]) {
                    grouped[s.attack_type] = {
                        attack_name: s.attack_name,
                        attack_icon: s.attack_icon,
                        items: []
                    };
                }
                grouped[s.attack_type].items.push(s);
            });
            
            // 渲染每个攻击类型组
            Object.entries(grouped).forEach(([attackType, group]) => {
                const groupDiv = document.createElement('div');
                groupDiv.className = 'attack-group';
                groupDiv.dataset.attackType = attackType;
                
                const header = document.createElement('div');
                header.className = 'attack-group-header';
                header.innerHTML = `
                    <span class="attack-group-icon">${group.attack_icon}</span>
                    <span class="attack-group-name">${group.attack_name}</span>
                    <span class="attack-group-count">${group.items.length} 个场景</span>
                `;
                groupDiv.appendChild(header);
                
                const body = document.createElement('div');
                body.className = 'attack-group-body';
                
                group.items.forEach(scenario => {
                    const btn = document.createElement('button');
                    btn.className = 'scenario-btn attack-btn';
                    btn.dataset.scenarioId = scenario.id;
                    btn.title = scenario.description;
                    
                    const suiteIcon = scenario.suite === 'workspace' ? '📋' : '🏦';
                    btn.innerHTML = `
                        ${suiteIcon} ${scenario.user_task_id} + ${scenario.injection_task_id}
                        <span class="attack-badge">${group.attack_icon}</span>
                    `;
                    
                    btn.addEventListener('click', () => this._executeAttackScenario(scenario));
                    
                    body.appendChild(btn);
                });
                
                groupDiv.appendChild(body);
                presetSection.appendChild(groupDiv);
            });
            
            container.appendChild(presetSection);
            
        } catch (err) {
            console.error('加载攻击场景列表失败:', err);
            container.innerHTML = '<p class="hint">加载攻击场景失败，请检查后端服务</p>';
        }
    },

    /**
     * 填充攻击选择器的选项
     */
    _populateAttackSelectors() {
        const suiteSelect = document.getElementById('attackSuiteSelect');
        const userTaskSelect = document.getElementById('attackUserTaskSelect');
        const injTaskSelect = document.getElementById('attackInjectionTaskSelect');
        if (!userTaskSelect || !injTaskSelect) return;
        
        const currentSuite = suiteSelect ? suiteSelect.value : 'workspace';
        
        // 填充 user_tasks
        userTaskSelect.innerHTML = '<option value="">-- 选择用户任务 --</option>';
        this._attackUserTasks
            .filter(t => t.suite === currentSuite)
            .forEach(t => {
                const opt = document.createElement('option');
                opt.value = t.id;
                opt.textContent = `${t.id}: ${t.prompt.substring(0, 60)}...`;
                opt.title = t.prompt;
                userTaskSelect.appendChild(opt);
            });
        
        // 填充 injection_tasks
        injTaskSelect.innerHTML = '<option value="">-- 选择注入任务 --</option>';
        this._attackInjectionTasks
            .filter(t => t.suite === currentSuite)
            .forEach(t => {
                const opt = document.createElement('option');
                opt.value = t.id;
                opt.textContent = `${t.id}: ${t.goal.substring(0, 60)}...`;
                opt.title = t.goal;
                injTaskSelect.appendChild(opt);
            });
    },

    /**
     * 绑定攻击选择器事件
     */
    _bindAttackSelectorEvents() {
        const suiteSelect = document.getElementById('attackSuiteSelect');
        if (suiteSelect) {
            suiteSelect.addEventListener('change', () => this._populateAttackSelectors());
        }
        
        const executeBtn = document.getElementById('btnExecuteCustomAttack');
        if (executeBtn) {
            executeBtn.addEventListener('click', () => this._executeCustomAttack());
        }
    },

    /**
     * 执行自定义攻击组合
     */
    async _executeCustomAttack() {
        if (this._isExecuting) return;
        
        const suiteSelect = document.getElementById('attackSuiteSelect');
        const typeSelect = document.getElementById('attackTypeSelect');
        const userTaskSelect = document.getElementById('attackUserTaskSelect');
        const injTaskSelect = document.getElementById('attackInjectionTaskSelect');
        
        if (!suiteSelect || !typeSelect || !userTaskSelect || !injTaskSelect) return;
        
        const suite = suiteSelect.value;
        const attackType = typeSelect.value;
        const userTaskId = userTaskSelect.value;
        const injTaskId = injTaskSelect.value;
        
        if (!userTaskId || !injTaskId) {
            this._showFeedback('⚠️ 请选择用户任务和注入任务', 'warning');
            return;
        }
        
        // 查找对应的任务信息
        const utInfo = this._attackUserTasks.find(t => t.id === userTaskId);
        const injInfo = this._attackInjectionTasks.find(t => t.id === injTaskId);
        
        const scenario = {
            id: `custom_${attackType}_${suite}_${userTaskId}_${injTaskId}`,
            attack_type: attackType,
            attack_name: typeSelect.options[typeSelect.selectedIndex]?.text?.replace(/^[^\s]+\s/, '') || attackType,
            attack_icon: typeSelect.options[typeSelect.selectedIndex]?.text?.charAt(0) || '🔴',
            suite: suite,
            user_task_id: userTaskId,
            injection_task_id: injTaskId,
            user_task_prompt: utInfo?.prompt || '',
            injection_goal: injInfo?.goal || '',
            name: `自定义: ${userTaskId} + ${injTaskId}`,
            description: `用户任务: ${utInfo?.prompt?.substring(0, 40) || ''}... | 注入目标: ${injInfo?.goal?.substring(0, 40) || ''}...`,
        };
        
        await this._executeAttackScenario(scenario);
    },

    /**
     * 执行攻击场景
     */
    async _executeAttackScenario(scenario) {
        if (this._isExecuting) return;
        
        this._isExecuting = true;
        this._showFeedback(`⏳ 正在执行攻击场景: ${scenario.attack_name} (${scenario.user_task_id} + ${scenario.injection_task_id})...`, 'info');
        
        try {
            const params = {
                user_task_id: scenario.user_task_id,
                injection_task_id: scenario.injection_task_id,
                attack_type: scenario.attack_type,
                suite: scenario.suite,
            };
            
            const result = await API.executeAttack(params);
            
            if (result.error) {
                this._showFeedback(`❌ ${result.error}`, 'error');
                return;
            }
            
            // 更新图谱
            if (result.graph && result.graph.nodes && result.graph.nodes.length > 0) {
                GRAPH.setData(result.graph.nodes, result.graph.links);
                GRAPH.render();
                const riskCardCount = result.risk_cards?.length || 0;
                GRAPH.updateStats(result.summary, riskCardCount);
            } else {
                await GRAPH.loadData();
            }
            
            // 更新事件时间线
            if (result.events) {
                TIMELINE.loadEvents(result.events);
            } else {
                try {
                    const events = await API.getEvents();
                    if (events) TIMELINE.loadEvents(events);
                } catch(e) {}
            }
            
            // 更新风险卡片
            RISK_PANEL.loadRiskCards();
            
            // 渲染追踪面板
            // 注意：后端 _build_trace_steps_from_messages 已包含阻断步骤，前端不再重复添加
            if (result.steps && result.steps.length > 0) {
                TRACE_PANEL._renderTrace({
                    trace_id: result.trace_id || scenario.id,
                    command: `${scenario.attack_name}: ${scenario.user_task_id} + ${scenario.injection_task_id}`,
                    llm_mode: 'real',
                    steps: result.steps,
                    total_steps: result.steps.length,
                });
            }
            
            // 显示执行结果
            if (result.blocked) {
                const riskCount = result.risk_cards?.length || 0;
                const reasons = result.risk_cards?.map(c => c.detail).join('; ') || '';
                this._showFeedback(`🚫 攻击已被防御系统阻断！(${riskCount} 个风险卡片) ${reasons ? '原因: ' + reasons.substring(0, 100) : ''}`, 'error');
            } else {
                this._showFeedback(`⚠️ 攻击场景执行完成（防御系统未阻断）`, 'warning');
            }
            
            // 更新统计
            const nodeCount = result.graph?.nodes?.length || 0;
            const edgeCount = result.graph?.links?.length || 0;
            if (nodeCount > 0) {
                Store.set('lastNodeCount', nodeCount);
                Store.set('lastEdgeCount', edgeCount);
            }
            
        } catch (err) {
            console.error('执行攻击场景失败:', err);
            this._showFeedback(`❌ 执行失败: ${err.message}`, 'error');
        } finally {
            this._isExecuting = false;
        }
    },
};
