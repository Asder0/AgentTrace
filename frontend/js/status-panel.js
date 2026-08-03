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
            <div class="status-panel-header" id="statusPanelHeader">
                <h3>🩺 系统状态</h3>
                <span class="status-panel-toggle" id="statusPanelToggle">▼</span>
            </div>
            <div class="status-panel-body" id="statusPanelBody">
                <!-- 系统概览 -->
                <div class="status-overview">
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotCapture">⚪</span>
                        <span>Capture</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotModeling">⚪</span>
                        <span>Modeling</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotAnalysis">⚪</span>
                        <span>Analysis</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotVisualization">⚪</span>
                        <span>Visualization</span>
                    </div>
                    <div class="status-overview-item">
                        <span class="status-overview-dot" id="statusDotExecution">⚪</span>
                        <span>Execution</span>
                    </div>
                </div>

                <!-- LLM 模式 -->
                <div class="status-section">
                    <div class="status-section-title">🤖 LLM 模式</div>
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
                    <div class="status-section-title">🛡️ 防御机制</div>
                    <div class="status-info-row">
                        <span class="status-info-label">状态</span>
                        <span class="status-info-value" id="statusDefenseMode">加载中...</span>
                    </div>
                </div>

                <!-- 图谱统计 -->
                <div class="status-section">
                    <div class="status-section-title">🌐 图谱统计</div>
                    <div class="status-info-row">
                        <span class="status-info-label">节点数</span>
                        <span class="status-info-value" id="statusGraphNodes">0</span>
                    </div>
                    <div class="status-info-row">
                        <span class="status-info-label">边数</span>
                        <span class="status-info-value" id="statusGraphEdges">0</span>
                    </div>
                </div>

                <!-- 功能清单 -->
                <div class="status-section">
                    <div class="status-section-title">📋 功能清单</div>
                    <div class="status-features" id="statusFeatures">
                        <p class="hint">加载中...</p>
                    </div>
                </div>

                <!-- 刷新按钮 -->
                <button class="status-refresh-btn" id="statusRefreshBtn">🔄 刷新状态</button>
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
        if (body) {
            body.style.display = this._expanded ? 'block' : 'none';
        }
        if (toggle) {
            toggle.textContent = this._expanded ? '▼' : '▶';
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
            }
        } catch (err) {
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
                dot.textContent = layerStatus ? '🟢' : '🔴';
                dot.title = layerStatus ? `${layer}: 正常运行` : `${layer}: 异常`;
            }
        }

        // 更新 LLM 模式
        const modeEl = document.getElementById('statusLLMMode');
        if (modeEl) {
            const isReal = status.llm_mode === 'real';
            const isConfigured = status.llm_config?.has_api_key;
            if (isReal && isConfigured) {
                modeEl.textContent = '🟢 真实 LLM（已配置）';
                modeEl.className = 'status-info-value status-ok';
            } else if (isReal && !isConfigured) {
                modeEl.textContent = '🟡 真实 LLM（未配置 API Key）';
                modeEl.className = 'status-info-value status-warn';
            } else {
                modeEl.textContent = '🔴 未配置';
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
        if (defenseEl) {
            const defenseEnabled = status.defense_enabled;
            if (defenseEnabled === true) {
                defenseEl.textContent = '🟢 已启用';
                defenseEl.className = 'status-info-value status-ok';
            } else if (defenseEnabled === false) {
                defenseEl.textContent = '🔴 已关闭';
                defenseEl.className = 'status-info-value status-warn';
            } else {
                defenseEl.textContent = '⚪ 未知';
                defenseEl.className = 'status-info-value';
            }
        }

        // 更新图谱统计
        const nodesEl = document.getElementById('statusGraphNodes');
        if (nodesEl && status.graph_stats) {
            nodesEl.textContent = status.graph_stats.nodes || 0;
        }

        const edgesEl = document.getElementById('statusGraphEdges');
        if (edgesEl && status.graph_stats) {
            edgesEl.textContent = status.graph_stats.edges || 0;
        }

        // 更新功能清单
        this._updateFeatures(status.features);
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
            
            html += `<div class="status-feature-layer">${layer}</div>`;
            for (const f of grouped[layer]) {
                const statusIcon = f.status ? '✅' : '❌';
                const statusClass = f.status ? 'feature-ok' : 'feature-fail';
                html += `
                    <div class="status-feature-item ${statusClass}">
                        <span class="status-feature-icon">${statusIcon}</span>
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
