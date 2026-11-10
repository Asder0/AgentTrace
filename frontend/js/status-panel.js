/**
 * 系统状态面板 - 显示系统各模块运行状态和功能清单
 * 
 * 提供：
 * - 系统健康检查（各层状态）
 * - 功能清单（可用/不可用功能）
 * - LLM 配置状态
 * - 图谱数据统计
 * - 自动刷新
 */
const STATUS_PANEL = {
    /** 自动刷新定时器 */
    _refreshTimer: null,
    
    /** 是否已展开 */
    _expanded: false,

    /**
     * 初始化状态面板
     */
    init() {
        this._createPanel();
        this._bindEvents();
        this._startAutoRefresh();
    },

    /**
     * 创建状态面板 DOM
     */
    _createPanel() {
        const sidePanel = document.querySelector('.side-panel');
        if (!sidePanel) return;

        const panel = document.createElement('div');
        panel.className = 'card status-panel';
        panel.id = 'statusPanel';
        panel.innerHTML = `
            <div class="status-panel-header"
                 id="statusPanelHeader"
                 role="button"
                 tabindex="0"
                 aria-expanded="false"
                 aria-controls="statusPanelBody">
                <h3>系统状态</h3>
                <span class="status-panel-toggle" id="statusPanelToggle" aria-hidden="true">▶</span>
            </div>
            <div class="status-panel-body" id="statusPanelBody" hidden>
                <!-- 系统概览 -->
                <div class="status-overview">
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotCapture"></span>
                        <span>数据捕获</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotModeling"></span>
                        <span>溯源建模</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotAnalysis"></span>
                        <span>风险分析</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotVisualization"></span>
                        <span>可视化服务</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotExecution"></span>
                        <span>执行服务</span>
                    </div>
                </div>

                <!-- LLM 模式 -->
                <div class="status-section">
                    <div class="status-section-title">LLM 模式</div>
                    <div class="status-info-row">
                        <span class="status-info-label">模式</span>
                        <span class="status-info-value" id="statusLLMMode">加载中...</span>
                    </div>
                    <div class="status-info-row">
                        <span class="status-info-label">提供商</span>
                        <span class="status-info-value" id="statusLLMProvider">-</span>
                    </div>
                    <div class="status-info-row">
                        <span class="status-info-label">模型</span>
                        <span class="status-info-value" id="statusLLMModel">-</span>
                    </div>
                </div>

                <!-- 防御机制 -->
                <div class="status-section">
                    <div class="status-section-title">防御机制</div>
                    <div class="status-info-row">
                        <span class="status-info-label">状态</span>
                        <span class="status-info-value" id="statusDefenseMode">加载中...</span>
                    </div>
                    <div class="status-ring-grid" id="statusDefenseRings"></div>
                </div>

                <!-- 图谱统计 -->
                <div class="status-section">
                    <div class="status-section-title">图谱统计</div>
                    <div class="status-info-row">
                        <span class="status-info-label">当前节点</span>
                        <span class="status-info-value" id="statusGraphNodes">0</span>
                    </div>
                    <div class="status-info-row">
                        <span class="status-info-label">当前关系</span>
                        <span class="status-info-value" id="statusGraphEdges">0</span>
                    </div>
                </div>

                <!-- 功能清单 -->
                <div class="status-section">
                    <div class="status-section-title">功能清单</div>
                    <div class="status-features" id="statusFeatures">
                        <p class="hint">加载中...</p>
                    </div>
                </div>

                <!-- 刷新按钮 -->
                <button class="status-refresh-btn" id="statusRefreshBtn" type="button">刷新状态</button>
                <div class="status-refresh-meta" id="statusRefreshMeta"></div>
            </div>
        `;

        // 插入到控制台之前
        const consoleCard = document.querySelector('.console-card');
        if (consoleCard) {
            sidePanel.insertBefore(panel, consoleCard);
        } else {
            sidePanel.prepend(panel);
        }
    },

    /**
     * 绑定事件
     */
    _bindEvents() {
        // 展开/折叠
        const header = document.getElementById('statusPanelHeader');
        if (header) {
            header.addEventListener('click', () => {
                this._toggleExpand();
            });
            header.addEventListener('keydown', (event) => {
                if (event.key !== 'Enter' && event.key !== ' ') return;
                event.preventDefault();
                this._toggleExpand();
            });
        }

        // 刷新按钮
        const refreshBtn = document.getElementById('statusRefreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.refresh();
            });
        }
    },

    /**
     * 切换展开/折叠
     */
    _toggleExpand() {
        this._expanded = !this._expanded;
        const body = document.getElementById('statusPanelBody');
        const toggle = document.getElementById('statusPanelToggle');
        const header = document.getElementById('statusPanelHeader');
        if (body) {
            body.hidden = !this._expanded;
        }
        if (toggle) {
            toggle.textContent = this._expanded ? '▼' : '▶';
        }
        if (header) {
            header.setAttribute(
                'aria-expanded',
                this._expanded ? 'true' : 'false',
            );
        }
    },

    /**
     * 启动自动刷新
     */
    _startAutoRefresh() {
        this.refresh();
        this._refreshTimer = setInterval(() => {
            this.refresh();
        }, 10000); // 每 10 秒刷新
    },

    /**
     * 刷新系统状态
     */
    async refresh() {
        try {
            const status = await API.getSystemStatus();
            if (status && status.status === 'ok') {
                this._updateStatus(status);
            } else {
                throw new Error('invalid status response');
            }
        } catch (err) {
            const meta = document.getElementById('statusRefreshMeta');
            if (meta) {
                meta.textContent = '刷新失败，显示上一次状态';
                meta.className = 'status-refresh-meta stale';
            }
            console.warn('刷新系统状态失败:', err.message);
        }
    },

    /**
     * 更新状态显示
     */
    _updateStatus(status) {
        // 更新各层状态点
        const layerDots = {
            'Capture': 'statusDotCapture',
            'Modeling': 'statusDotModeling',
            'Analysis': 'statusDotAnalysis',
            'Visualization': 'statusDotVisualization',
            'Execution': 'statusDotExecution',
        };

        for (const [layer, dotId] of Object.entries(layerDots)) {
            const dot = document.getElementById(dotId);
            if (dot && status.layers && status.layers[layer]) {
                const layerStatus = status.layers[layer].status;
                dot.className = `status-overview-dot ${layerStatus ? 'ok' : 'fail'}`;
                dot.title = layerStatus ? `${layer}: 正常运行` : `${layer}: 异常`;
            }
        }

        for (const [layer, dotId] of Object.entries(layerDots)) {
            const dot = document.getElementById(dotId);
            if (!dot || !status.layers?.[layer]) continue;
            const layerLabel = window.AgentTraceRiskLabels?.layerLabel
                ? window.AgentTraceRiskLabels.layerLabel(layer)
                : layer;
            dot.title = status.layers[layer].status
                ? `${layerLabel}：正常运行`
                : `${layerLabel}：异常`;
        }

        // 更新 LLM 模式
        const modeEl = document.getElementById('statusLLMMode');
        if (modeEl) {
            const isReal = status.llm_mode === 'real';
            const isConfigured = status.llm_config?.has_api_key;
            if (isReal && isConfigured) {
                modeEl.textContent = '真实 LLM（已配置）';
                modeEl.className = 'status-info-value status-ok';
            } else if (isReal && !isConfigured) {
                modeEl.textContent = '真实 LLM（未配置 API Key）';
                modeEl.className = 'status-info-value status-warn';
            } else {
                modeEl.textContent = '未配置';
                modeEl.className = 'status-info-value status-fail';
            }
        }

        const providerEl = document.getElementById('statusLLMProvider');
        if (providerEl && status.llm_config) {
            providerEl.textContent = status.llm_config.provider || '-';
        }

        const modelEl = document.getElementById('statusLLMModel');
        if (modelEl && status.llm_config) {
            modelEl.textContent = status.llm_config.model || '-';
        }

        // 更新防御机制状态
        const defenseEl = document.getElementById('statusDefenseMode');
        const defenseRings = status.defense_rings || {};
        const ringStates = Object.values(defenseRings);
        const enabledRings = ringStates.filter(Boolean).length;
        if (defenseEl) {
            const defenseEnabled = status.defense_enabled;
            if (defenseEnabled === true) {
                if (ringStates.length && enabledRings === 0) {
                    defenseEl.textContent = '已关闭';
                    defenseEl.className = 'status-info-value status-warn';
                } else if (ringStates.length && enabledRings < ringStates.length) {
                    defenseEl.textContent = '部分启用';
                    defenseEl.className = 'status-info-value status-warn';
                } else {
                    defenseEl.textContent = '已启用';
                    defenseEl.className = 'status-info-value status-ok';
                }
            } else if (defenseEnabled === false) {
                defenseEl.textContent = '已关闭';
                defenseEl.className = 'status-info-value status-warn';
            } else {
                defenseEl.textContent = '未知';
                defenseEl.className = 'status-info-value';
            }
        }
        this._renderDefenseRings(defenseRings);

        // 更新当前画布规模（历史回放期间由回放数据接管）
        const replaying = typeof Store !== 'undefined' && Store.get('replaying');
        const displayedStats = (
            typeof GRAPH !== 'undefined'
            && typeof GRAPH.getDisplayedStats === 'function'
        )
            ? GRAPH.getDisplayedStats()
            : null;
        const nodesEl = document.getElementById('statusGraphNodes');
        if (!replaying && nodesEl) {
            nodesEl.textContent = displayedStats?.nodes
                ?? status.graph_stats?.nodes
                ?? 0;
        }

        const edgesEl = document.getElementById('statusGraphEdges');
        if (!replaying && edgesEl) {
            edgesEl.textContent = displayedStats?.relations
                ?? status.graph_stats?.edges
                ?? 0;
        }

        // 更新功能清单
        this._updateFeatures(status.features);
        const meta = document.getElementById('statusRefreshMeta');
        if (meta) {
            const refreshedAt = status.server_time
                ? new Date(status.server_time * 1000)
                : new Date();
            meta.textContent = `最近刷新 ${refreshedAt.toLocaleTimeString()}`;
            meta.className = 'status-refresh-meta';
        }
    },

    _renderDefenseRings(ringStates) {
        const container = document.getElementById('statusDefenseRings');
        if (!container) return;
        container.innerHTML = '';
        const labels = {
            ring_0: 'Ring 0',
            ring_1: 'Ring 1',
            ring_2: 'Ring 2',
            ring_3: 'Ring 3',
        };
        for (const ring of ['ring_0', 'ring_1', 'ring_2', 'ring_3']) {
            if (!(ring in ringStates)) continue;
            const enabled = Boolean(ringStates[ring]);
            const item = document.createElement('div');
            item.className = `status-ring-item ${enabled ? 'ok' : 'off'}`;

            const dot = document.createElement('span');
            dot.className = 'status-ring-dot';
            dot.setAttribute('aria-hidden', 'true');

            const label = document.createElement('span');
            label.textContent = labels[ring];

            const state = document.createElement('span');
            state.className = 'status-ring-state';
            state.textContent = enabled ? '启用' : '关闭';

            item.append(dot, label, state);
            container.appendChild(item);
        }
    },

    /**
     * 使用指定图谱规模刷新状态面板（用于历史回放）
     */
    setGraphStats(nodeCount, edgeCount) {
        const nodesEl = document.getElementById('statusGraphNodes');
        if (nodesEl) nodesEl.textContent = Number(nodeCount) || 0;

        const edgesEl = document.getElementById('statusGraphEdges');
        if (edgesEl) edgesEl.textContent = Number(edgeCount) || 0;
    },

    /**
     * 更新功能清单
     */
    _updateFeatures(features) {
        const container = document.getElementById('statusFeatures');
        if (!container || !features) return;

        // 按层分组
        const grouped = {};
        for (const f of features) {
            if (!grouped[f.layer]) {
                grouped[f.layer] = [];
            }
            grouped[f.layer].push(f);
        }

        let html = '';
        const layerOrder = ['Capture', 'Modeling', 'Analysis', 'Visualization', 'Execution'];
        for (const layer of layerOrder) {
            if (!grouped[layer]) continue;
            
            const layerLabel = window.AgentTraceRiskLabels?.layerLabel
                ? window.AgentTraceRiskLabels.layerLabel(layer)
                : layer;
            html += `<div class="status-feature-layer">${layerLabel}</div>`;
            for (const f of grouped[layer]) {
                const statusClass = f.status ? 'feature-ok' : 'feature-fail';
                html += `
                    <div class="status-feature-item ${statusClass}">
                        <span class="status-feature-icon"></span>
                        <span class="status-feature-name">${f.name}</span>
                    </div>
                `;
            }
        }

        container.innerHTML = html;
    },

    /**
     * 销毁（清理定时器）
     */
    destroy() {
        if (this._refreshTimer) {
            clearInterval(this._refreshTimer);
            this._refreshTimer = null;
        }
    }
};
