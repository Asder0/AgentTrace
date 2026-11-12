/**
 * 控制台模块 - 操作控制台
 * 
 * 提供跨 APP 预设任务和跨 APP 攻击测试。
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
 * - 跨 APP 攻击任务选择和执行
 * - 执行状态反馈
 */

const CONSOLE = {
    /** 当前是否正在执行操作 */
    _isExecuting: false,
    
    /** 当前 LLM 配置 */
    _llmConfig: {
        provider: 'deepseek',
        model: 'deepseek-flash',
        api_key: '',
    },

    /**
     * 初始化控制台
     */
    async init() {
        await this.loadScenarios();
        await this._loadLLMConfig();
        this._renderLLMConfigPanel();
        await this._initDefenseToggle();
        await this._loadAttackScenarios();
    },

    /**
     * 执行真实操作前退出历史回放状态，
     * 避免回放快照与新的实时执行结果混在一起。
     */
    _leaveReplay() {
        if (typeof APP !== 'undefined' && typeof APP.exitReplay === 'function') {
            APP.exitReplay({ reload: false });
        }
        // 新的实时执行会重新下发步骤，先清除上一次的步骤信息，避免错配
        if (typeof TIMELINE !== 'undefined' && typeof TIMELINE.clearTraceSteps === 'function') {
            TIMELINE.clearTraceSteps();
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

            const crossAppScenarios = scenarios.filter(
                scenario => scenario.cross_app
            );
            const composed = crossAppScenarios.filter(
                scenario => scenario.source?.benchmark === 'AgentDojo'
            );
            const appworld = crossAppScenarios.filter(
                scenario => scenario.source?.benchmark === 'AppWorld'
            );
            const handcrafted = crossAppScenarios.filter(
                scenario => !['AgentDojo', 'AppWorld'].includes(
                    scenario.source?.benchmark
                )
            );
            const baseline = scenarios.filter(
                scenario => !scenario.cross_app
            );
            container.innerHTML = '';
            container.appendChild(this._createScenarioGroup(
                'AgentDojo 组合',
                composed,
                true,
            ));
            container.appendChild(this._createScenarioGroup(
                'AppWorld 迁移',
                appworld,
                true,
            ));
            container.appendChild(this._createScenarioGroup(
                '手工跨 APP',
                handcrafted,
                false,
            ));
            if (baseline.length) {
                container.appendChild(this._createScenarioGroup(
                    '单 APP 基线（可选对比）',
                    baseline,
                    false,
                ));
            }
            
        } catch (err) {
            console.error('加载场景列表失败:', err);
            container.innerHTML = '<p class="hint">加载场景失败，请检查后端服务</p>';
        }
    },

    _createScenarioGroup(title, scenarios, open = false) {
        const details = document.createElement('details');
        details.className = 'scenario-group';
        details.open = open;

        const summary = document.createElement('summary');
        summary.className = 'scenario-group-summary';
        const label = document.createElement('span');
        label.textContent = title;
        const count = document.createElement('span');
        count.className = 'scenario-group-count';
        count.textContent = String(scenarios.length);
        summary.append(label, count);

        const body = document.createElement('div');
        body.className = 'scenario-group-body';
        scenarios.forEach((scenario) => {
            body.appendChild(this._createScenarioButton(scenario));
        });
        details.append(summary, body);
        return details;
    },

    _createScenarioButton(scenario) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'scenario-btn';
        if (scenario.cross_app) btn.classList.add('cross-app');
        if (!scenario.cross_app && scenario.cross_module) {
            btn.classList.add('cross-module');
        }
        btn.dataset.action = scenario.id;
        btn.title = this._cleanDisplayText(scenario.description);

        const rawLabel = scenario.cross_app
            ? (scenario.task_id || scenario.id)
            : (scenario.task_id && scenario.suite
                ? `${scenario.task_id} (${scenario.suite})`
                : (scenario.name || scenario.id));
        const label = document.createElement('span');
        label.className = 'scenario-btn-label';
        label.textContent = String(rawLabel).replace(
            /^appworld_/,
            'AppWorld · ',
        );
        btn.appendChild(label);

        const requiredSuites = scenario.required_suites || [];
        if (requiredSuites.length > 1) {
            const badge = document.createElement('span');
            badge.className = 'badge badge-cross';
            badge.textContent = `${requiredSuites.length} APP`;
            btn.appendChild(badge);
        }
        btn.addEventListener('click', () => this._executeScenario(scenario.id));
        return btn;
    },

    /**
     * 执行预设场景
     * 预设场景只发送 prompt 文本给后端，由 AgentPipeline 让 LLM 自主决策
     */
    async _executeScenario(action) {
        if (this._isExecuting) return;
        
        this._isExecuting = true;
        this._leaveReplay();
        this._showFeedback('正在执行操作；首次安全检查可能需要加载本地分类模型...', 'info');
        
        // 发布场景执行事件（触发追踪面板）
        
        try {
            const result = await API.executeAction(action);

            
            if (result.error) {
                this._showFeedback(`执行失败：${result.error}`, 'error');
                return;
            }
            
            // 更新图谱 - 优先使用返回的 graph 数据，否则强制从后端重新加载
            if (result.graph && result.graph.nodes && result.graph.nodes.length > 0) {
                GRAPH.setData(result.graph.nodes, result.graph.links, { suite: result.suite || null });
                GRAPH.render();
                const riskCardCount = result.risk_cards?.length || 0;
                GRAPH.updateStats(result.summary, riskCardCount, result.events?.length);
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
                TIMELINE.setTrace({
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
                const reasons = this._localizedRiskReasons(result);
                this._showFeedback(`操作已被阻断（${riskCount} 个风险事件）${reasons ? '；原因：' + reasons.substring(0, 100) : ''}`, 'error');
            } else if (result.status === 'incomplete') {
                const reason = this._localizedTaskReason(result);
                this._showFeedback(`任务未完成：${reason}`, 'warning');
            } else if ((result.risk_cards?.length || 0) > 0) {
                const reasons = this._localizedRiskReasons(result);
                this._showFeedback(`操作已执行，但存在风险提醒${reasons ? '；' + reasons.substring(0, 120) : ''}`, 'warning');
            } else {
                this._showFeedback(`操作执行成功（${modeText}）`, 'success');
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
            this._showFeedback(`执行失败：${err.message}`, 'error');
        } finally {
            this._isExecuting = false;
        }
    },

    _localizedRiskReasons(result) {
        const labels = window.AgentTraceRiskLabels;
        return (result?.risk_cards || [])
            .map(card => {
                const normalized = labels?.normalizeCard
                    ? labels.normalizeCard(card)
                    : card;
                return normalized.defense_detail || '';
            })
            .filter(Boolean)
            .join('；');
    },

    _localizedTaskReason(result) {
        const outcomes = result?.completion_audit?.outcomes || [];
        const unsatisfied = outcomes.filter(item =>
            String(item.status || '') === 'unsatisfied'
        );
        const uncertain = outcomes.filter(item =>
            String(item.status || '') === 'uncertain'
        );
        const reasons = [];
        if (unsatisfied.length) {
            reasons.push(
                `${unsatisfied.length} 项必需结果未满足`
                + `（${unsatisfied.map(item => item.id || '未命名结果').join('、')}）`
            );
        }
        if (uncertain.length) {
            reasons.push(
                `${uncertain.length} 项必需结果无法验证`
                + `（${uncertain.map(item => item.id || '未命名结果').join('、')}）`
            );
        }
        if (result?.task_stopped) {
            reasons.push(
                result.stop_reason === 'l2_egress_execution_uncertain'
                    ? 'L2 外发执行失败，已禁止自动重试；需要用户明确重新发起'
                    : '任务因结构化停止条件安全结束'
            );
        }
        return reasons.join('；') || '必需任务结果尚未全部完成';
    },

    /**
     * 显示反馈信息
     */
    _showFeedback(message, type = 'info') {
        const feedback = document.getElementById('consoleFeedback');
        if (!feedback) return;
        
        feedback.className = `console-feedback ${type || 'info'}`;
        feedback.textContent = message;
        feedback.hidden = false;
        if (typeof STORAGE_VIEW !== 'undefined') STORAGE_VIEW.notifyDataChanged();

        // 自动隐藏（错误和警告保留更长时间）
        const duration = type === 'error' ? 8000 : type === 'warning' ? 6000 : 4000;
        clearTimeout(this._feedbackTimer);
        this._feedbackTimer = setTimeout(() => {
            feedback.hidden = true;
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
                LLM 配置
                <span class="llm-status ${hasApiKey ? 'configured' : 'not-configured'}" id="llmStatus">${hasApiKey ? '已配置' : '未配置'}</span>
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
                    <button id="btnSaveLLMConfig" class="btn-execute llm-save-btn" type="button">保存配置</button>
                </div>
                <div class="llm-config-row">
                    <p class="llm-config-hint">
                        ${hasApiKey 
                            ? '真实 LLM 已配置，操作将通过 AgentPipeline 调用大模型 API 自主决策。'
                            : '请配置 API Key 以启用真实 LLM。用户指令将直接输入给大模型，大模型根据可用工具 API 自主决策工具调用。'}
                    </p>
                </div>
            </div>
            <!-- 防御机制开关 -->
            <div class="console-label llm-config-header defense-config-header">
                防御机制
                <span class="defense-status" id="defenseStatusText">加载中...</span>
            </div>
            <div class="llm-config-grid">
                <div class="llm-config-row">
                    <label class="llm-config-label">Analysis Pipeline</label>
                    <label class="toggle-switch">
                        <input type="checkbox" id="defenseToggle" checked>
                        <span class="toggle-slider"></span>
                    </label>
                    <span class="llm-config-help">关闭后跳过 Ring 0-3 检测</span>
                </div>
                <div class="llm-config-row llm-config-row-stack">
                    <div class="llm-config-help">Ring 级开关（可单独关闭/开启每个 Ring 及其内部检测方法）</div>
                    <div id="ringTogglesContainer" class="ring-config-list">
                        <!-- 动态渲染：每个 Ring 一行，含 Ring 开关 + 方法开关 -->
                    </div>
                </div>
                <div class="llm-config-row">
                    <label class="llm-config-label">自动同意确认</label>
                    <label class="toggle-switch">
                        <input type="checkbox" id="autoConfirmationsToggle" checked>
                        <span class="toggle-slider"></span>
                    </label>
                    <span class="llm-config-help">默认自动处理普通审批和任务要求解析；关闭后逐节点人工决策</span>
                </div>
            </div>
        `;
        
        // 在预设任务区域之后插入
        const scenarioSection = consoleCard.querySelector(
            '.console-section:first-child'
        );
        if (scenarioSection) {
            scenarioSection.after(llmSection);
        } else {
            consoleCard.appendChild(llmSection);
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

        const autoConfirmationsToggle = document.getElementById(
            'autoConfirmationsToggle'
        );
        if (autoConfirmationsToggle) {
            autoConfirmationsToggle.addEventListener('change', () => {
                this._updateAutoConfirmations();
            });
        }

        // Ring 级 / 方法级开关切换事件（事件委托）
        const ringContainer = document.getElementById('ringTogglesContainer');
        if (ringContainer) {
            ringContainer.addEventListener('change', (e) => {
                if (e.target && e.target.dataset && e.target.dataset.role) {
                    this._updateRingConfig();
                }
            });
        }
    },

    /**
     * 保存 LLM 配置
     */
    async _saveLLMConfig() {
        const provider = document.getElementById('llmProvider')?.value || 'deepseek';
        const model = document.getElementById('llmModel')?.value || 'deepseek-flash';
        const apiKey = document.getElementById('llmApiKey')?.value || '';
        
        if (!apiKey) {
            this._showFeedback('需要提供 API Key', 'warning');
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
                    statusEl.textContent = '已配置';
                    statusEl.className = 'llm-status configured';
                }
                
                // 清空 API Key 输入框（安全）
                const apiKeyInput = document.getElementById('llmApiKey');
                if (apiKeyInput) {
                    apiKeyInput.value = '';
                }
                
                this._showFeedback(
                    `LLM 配置已保存，已启用 ${provider}/${model}`,
                    'success'
                );
            } else {
                this._showFeedback('保存 LLM 配置失败', 'error');
            }
        } catch (err) {
            console.error('保存 LLM 配置失败:', err);
            this._showFeedback(`保存失败：${err.message}`, 'error');
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
            const autoConfirmationsToggle = document.getElementById(
                'autoConfirmationsToggle'
            );
            if (autoConfirmationsToggle) {
                autoConfirmationsToggle.checked =
                    config.auto_confirmations !== false;
            }
            if (statusText) {
                statusText.textContent = config.enabled ? '已启用' : '已关闭';
                statusText.className = config.enabled ? 'defense-status enabled' : 'defense-status disabled';
            }
            this._renderRingToggles(
                config.rings || {},
                config.direct_injection_mode || config.user_anchor_mode || 'quarantine'
            );
        } catch (err) {
            console.warn('获取防御配置失败:', err.message);
        }
    },

    /**
     * 渲染每个 Ring 的开关行（Ring 开关 + 硬编码检测方法开关）
     */
    _renderRingToggles(rings, directInjectionMode = 'quarantine') {
        const container = document.getElementById('ringTogglesContainer');
        if (!container || !rings) return;

        const ringNames = {
            ring_0: 'Ring 0 · 初始 Prompt 注入检测',
            ring_1: 'Ring 1 · 不可信控制流提醒',
            ring_2: 'Ring 2 · 任务工具范围检查',
            ring_3: 'Ring 3 · 敏感数据外发检查',
        };

        const rows = Object.keys(rings).map((ring) => {
            const cfg = rings[ring] || {};
            const enabled = !!cfg.enabled;
            const methodFlags = cfg.methods || {};
            const methodLabels = cfg.method_labels || {};
            const methodToggles = Object.keys(methodFlags).map((method) => {
                const checked = methodFlags[method] ? 'checked' : '';
                const label = methodLabels[method] || method;
                return `
                    <label class="ring-method">
                        <input type="checkbox" data-role="method" data-ring="${ring}" data-method="${method}" ${checked}>
                        <span title="${label}">${method}</span>
                    </label>
                `;
            }).join('');
            return `
                <div class="ring-config-item">
                    <label class="ring-config-label">
                        <input type="checkbox" data-role="ring" data-ring="${ring}" ${enabled ? 'checked' : ''}>
                        <span>${ringNames[ring] || ring}</span>
                    </label>
                    <div class="ring-method-list">
                        ${methodToggles}
                    </div>
                </div>
            `;
        }).join('');
        container.innerHTML = `
            <div class="ring-config-item">
                <label class="ring-config-label">
                    <span>直接注入处理模式</span>
                </label>
                <select data-role="direct-injection-mode" class="ring-method">
                    <option value="advisory" ${directInjectionMode === 'advisory' ? 'selected' : ''}>ADVISORY · 仅记录风险，不修改输入</option>
                    <option value="quarantine" ${directInjectionMode === 'quarantine' ? 'selected' : ''}>QUARANTINE · 替换风险块后继续</option>
                    <option value="strict" ${directInjectionMode === 'strict' ? 'selected' : ''}>STRICT · 检测到风险直接阻断</option>
                </select>
            </div>
            ${rows}
        `;
    },

    /**
     * 将当前 Ring 级/方法级开关状态提交到后端
     */
    async _updateRingConfig() {
        const container = document.getElementById('ringTogglesContainer');
        if (!container) return;

        const rings = {};
        container.querySelectorAll('input[data-role="ring"]').forEach((el) => {
            const ring = el.dataset.ring;
            if (!rings[ring]) rings[ring] = {};
            rings[ring].enabled = el.checked;
        });
        container.querySelectorAll('input[data-role="method"]').forEach((el) => {
            const ring = el.dataset.ring;
            if (!rings[ring]) rings[ring] = {};
            if (!rings[ring].methods) rings[ring].methods = {};
            rings[ring].methods[el.dataset.method] = el.checked;
        });

        try {
            const anchorSelect = container.querySelector('select[data-role="direct-injection-mode"]');
            const result = await API.setDefenseConfig(
                null,
                rings,
                anchorSelect ? anchorSelect.value : null
            );
            if (result && result.status === 'ok') {
                this._showFeedback('Ring/检测方法开关已更新', 'info');
            }
        } catch (err) {
            console.error('设置 Ring 配置失败:', err);
            this._showFeedback(`设置 Ring 配置失败：${err.message}`, 'error');
            // 重新拉取配置，恢复实际状态
            try {
                const config = await API.getDefenseConfig();
                this._renderRingToggles(
                    config.rings || {},
                    config.direct_injection_mode || config.user_anchor_mode || 'quarantine'
                );
            } catch (e) { /* ignore */ }
        }
    },

    async _updateAutoConfirmations() {
        const toggle = document.getElementById('autoConfirmationsToggle');
        if (!toggle) return;
        const enabled = toggle.checked;
        try {
            const result = await API.setDefenseConfig(
                null,
                null,
                null,
                enabled
            );
            if (result && result.status === 'ok') {
                this._showFeedback(
                    enabled
                        ? '已开启自动同意，普通审批和要求解析将自动处理'
                        : '已关闭自动同意，后续确认节点需要人工决策',
                    'info'
                );
            }
        } catch (err) {
            toggle.checked = !enabled;
            console.error('设置自动同意策略失败:', err);
            this._showFeedback(
                `设置自动同意策略失败：${err.message}`,
                'error'
            );
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
                    statusText.textContent = enabled ? '已启用' : '已关闭';
                    statusText.className = enabled ? 'defense-status enabled' : 'defense-status disabled';
                }
                this._showFeedback(
                    enabled ? '防御机制已启用' : '防御机制已关闭',
                    'info'
                );
            }
        } catch (err) {
            console.error('设置防御配置失败:', err);
            // 恢复开关状态
            toggle.checked = !enabled;
            this._showFeedback(`设置防御配置失败：${err.message}`, 'error');
        }
    },

    // ============================================================
    // 攻击场景
    // ============================================================

    _attackTargets: [],
    _attackTypes: [],
    _attackGoals: [],

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
            const payload = await API.getCrossAppAttackTargets();
            this._attackTargets = Array.isArray(payload?.targets)
                ? payload.targets
                : [];
            this._attackTypes = Array.isArray(payload?.attack_types)
                ? payload.attack_types
                : [];
            this._attackGoals = Array.isArray(payload?.goals)
                ? payload.goals
                : [];

            if (!this._attackTargets.length) {
                container.innerHTML = '<p class="hint">暂无跨 APP 攻击任务</p>';
                return;
            }

            container.innerHTML = '';
            const section = document.createElement('div');
            section.className = 'attack-selector-section';
            section.innerHTML = `
                <div class="attack-selector-title">跨 APP 攻击测试</div>
                <div class="attack-selector-grid">
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">任务</label>
                        <select id="attackCrossAppTaskSelect" class="attack-selector-select">
                            ${this._attackTargets.map(target => `
                                <option value="${this._escape(target.id)}">
                                    ${this._escape(target.task_id)}
                                </option>
                            `).join('')}
                        </select>
                    </div>
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">注入位置</label>
                        <select id="attackInjectionPointSelect" class="attack-selector-select"></select>
                    </div>
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">攻击模板</label>
                        <select id="attackTypeSelect" class="attack-selector-select">
                            ${this._attackTypes.map(item => `
                                <option value="${this._escape(item.id)}">
                                    ${this._escape(item.name)}
                                </option>
                            `).join('')}
                        </select>
                    </div>
                    <div class="attack-selector-row">
                        <label class="attack-selector-label">恶意目标</label>
                        <select id="attackGoalSelect" class="attack-selector-select">
                            ${this._attackGoals.map(item => `
                                <option value="${this._escape(item.id)}">
                                    ${this._escape(item.name)}
                                </option>
                            `).join('')}
                        </select>
                    </div>
                    <div class="attack-selector-row attack-selector-actions">
                        <button id="btnExecuteCrossAppAttack"
                                class="btn-execute attack-execute-btn"
                                type="button">执行跨 APP 攻击</button>
                    </div>
                    <div class="attack-target-summary" id="attackTargetSummary"></div>
                </div>
            `;
            container.appendChild(section);
            this._populateAttackTargetDetails();
            this._bindAttackSelectorEvents();
        } catch (err) {
            console.error('加载跨 APP 攻击场景失败:', err);
            container.innerHTML = '<p class="hint">加载跨 APP 攻击场景失败，请检查后端服务</p>';
        }
    },

    /**
     * 展示层文本清洗：避免依赖后端拼接图标/装饰符号。
     * 仅用于按钮 tooltip 等展示文本。
     */
    _cleanDisplayText(text) {
        return String(text == null ? '' : text)
            .replace(/[\u{1F000}-\u{1FAFF}\u{2190}-\u{2BFF}\u{FE0F}\u{200D}]/gu, '')
            .replace(/\s+/g, ' ')
            .trim();
    },

    _escape(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    },

    /**
     * 填充攻击选择器的选项
     */
    _populateAttackTargetDetails() {
        const taskSelect = document.getElementById(
            'attackCrossAppTaskSelect'
        );
        const pointSelect = document.getElementById(
            'attackInjectionPointSelect'
        );
        const summary = document.getElementById('attackTargetSummary');
        if (!taskSelect || !pointSelect || !summary) return;

        const target = this._attackTargets.find(
            item => item.id === taskSelect.value
        );
        pointSelect.innerHTML = '';
        if (!target) {
            summary.textContent = '';
            return;
        }
        for (const point of target.injection_points || []) {
            const option = document.createElement('option');
            option.value = point.id;
            option.textContent = point.label;
            option.title = point.preview;
            pointSelect.appendChild(option);
        }
        const suites = target.required_suites || [];
        const sourceLabels = {
            appworld: 'AppWorld 迁移',
            agentdojo: 'AgentDojo 组合',
            handcrafted: '手工跨 APP',
        };
        const sourceLabel = sourceLabels[target.source_kind]
            || '自定义跨 APP';
        summary.textContent = [
            sourceLabel,
            `${suites.length} 个 APP：${suites.join(' → ')}`,
            target.description || '',
        ].filter(Boolean).join(' · ');
    },

    /**
     * 绑定攻击选择器事件
     */
    _bindAttackSelectorEvents() {
        const taskSelect = document.getElementById(
            'attackCrossAppTaskSelect'
        );
        if (taskSelect) {
            taskSelect.addEventListener(
                'change',
                () => this._populateAttackTargetDetails(),
            );
        }
        
        const executeBtn = document.getElementById('btnExecuteCrossAppAttack');
        if (executeBtn) {
            executeBtn.addEventListener('click', () => this._executeSelectedAttack());
        }
    },

    async _executeSelectedAttack() {
        if (this._isExecuting) return;

        const taskSelect = document.getElementById(
            'attackCrossAppTaskSelect'
        );
        const pointSelect = document.getElementById(
            'attackInjectionPointSelect'
        );
        const typeSelect = document.getElementById('attackTypeSelect');
        const goalSelect = document.getElementById('attackGoalSelect');
        if (!taskSelect || !pointSelect || !typeSelect || !goalSelect) {
            return;
        }

        const crossAppTaskId = taskSelect.value;
        const injectionPointId = pointSelect.value;
        const attackType = typeSelect.value;
        const goalId = goalSelect.value;
        if (!crossAppTaskId || !injectionPointId || !goalId) {
            this._showFeedback('请选择跨 APP 任务、注入位置和恶意目标', 'warning');
            return;
        }

        const target = this._attackTargets.find(
            item => item.id === crossAppTaskId
        );
        const goal = this._attackGoals.find(item => item.id === goalId);
        const attackTypeInfo = this._attackTypes.find(
            item => item.id === attackType
        );
        const scenario = {
            id: `cross_attack_${attackType}_${crossAppTaskId}`,
            attack_type: attackType,
            attack_name: attackTypeInfo?.name || attackType,
            suite: 'unified',
            cross_app_task_id: crossAppTaskId,
            injection_point_id: injectionPointId,
            injection_goal_id: goalId,
            user_task_label: target?.task_id || crossAppTaskId,
            injection_task_label: goal?.name || goalId,
            injection_goal: goal?.goal || '',
            name: `${attackTypeInfo?.name || attackType}: ${target?.task_id || crossAppTaskId}`,
        };
        await this._executeAttackScenario(scenario);
    },

    /**
     * 执行攻击场景
     */
    async _executeAttackScenario(scenario) {
        if (this._isExecuting) return;
        
        this._isExecuting = true;
        this._leaveReplay();
        this._showFeedback(`正在执行攻击场景：${scenario.attack_name} (${scenario.user_task_label || scenario.user_task_id} + ${scenario.injection_task_label || scenario.injection_task_id})...`, 'info');
        
        try {
            const params = scenario.cross_app_task_id
                ? {
                    cross_app_task_id: scenario.cross_app_task_id,
                    injection_point_id: scenario.injection_point_id,
                    injection_goal_id: scenario.injection_goal_id,
                    attack_type: scenario.attack_type,
                    suite: 'unified',
                }
                : {
                    user_task_id: scenario.user_task_id,
                    injection_task_id: scenario.injection_task_id,
                    attack_type: scenario.attack_type,
                    suite: scenario.suite,
                };
            
            const result = await API.executeAttack(params);
            
            if (result.error) {
                this._showFeedback(`执行失败：${result.error}`, 'error');
                return;
            }
            
            // 更新图谱
            if (result.graph && result.graph.nodes && result.graph.nodes.length > 0) {
                GRAPH.setData(result.graph.nodes, result.graph.links, { suite: result.suite || null });
                GRAPH.render();
                const riskCardCount = result.risk_cards?.length || 0;
                GRAPH.updateStats(result.summary, riskCardCount, result.events?.length);
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
                TIMELINE.setTrace({
                    trace_id: result.trace_id || scenario.id,
                    command: `${scenario.attack_name}: ${scenario.user_task_label || scenario.user_task_id} + ${scenario.injection_task_label || scenario.injection_task_id}`,
                    llm_mode: 'real',
                    steps: result.steps,
                    total_steps: result.steps.length,
                });
            }
            
            // 显示执行结果
            if (result.blocked) {
                const riskCount = result.risk_cards?.length || 0;
                const reasons = this._localizedRiskReasons(result);
                this._showFeedback(`攻击已被防御系统阻断（${riskCount} 个风险事件）${reasons ? '；原因：' + reasons.substring(0, 100) : ''}`, 'error');
            } else if (result.status === 'incomplete') {
                const reason = this._localizedTaskReason(result);
                this._showFeedback(`攻击场景执行未完成：${reason}`, 'warning');
            } else if ((result.risk_cards?.length || 0) > 0) {
                const reasons = this._localizedRiskReasons(result);
                this._showFeedback(`攻击场景已执行，风险已高亮提醒${reasons ? '；' + reasons.substring(0, 120) : ''}`, 'warning');
            } else {
                this._showFeedback('攻击场景执行完成（防御系统未阻断）', 'warning');
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
            this._showFeedback(`执行失败：${err.message}`, 'error');
        } finally {
            this._isExecuting = false;
        }
    },
};
