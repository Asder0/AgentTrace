/**
 * 主入口模块 - AgentDojo 数据流追踪可视化平台
 * 
 * 初始化所有模块，协调数据加载和页面交互。
 * 
 * 增强功能：
 * - 统一状态管理（Store）
 * - 事件发布/订阅模式
 * - 优化轮询逻辑（增量更新检测）
 * - 加载状态管理
 * - 错误边界处理
 */

// ============================================================
// 全局状态管理
// ============================================================
const Store = {
    _state: {
        loading: true,
        error: null,
        lastNodeCount: 0,
        lastEdgeCount: 0,
        isPolling: false,
        replaying: false,
    },
    
    _listeners: {},
    
    get(key) {
        return this._state[key];
    },
    
    set(key, value) {
        const old = this._state[key];
        this._state[key] = value;
        this._emit(key, value, old);
    },
    
    on(event, callback) {
        if (!this._listeners[event]) {
            this._listeners[event] = [];
        }
        this._listeners[event].push(callback);
    },
    
    _emit(event, newVal, oldVal) {
        (this._listeners[event] || []).forEach(cb => cb(newVal, oldVal));
    },
    
    // 全局事件总线
    publish(event, data) {
        (this._listeners[event] || []).forEach(cb => cb(data));
    },
    
    subscribe(event, callback) {
        this.on(event, callback);
    }
};

// ============================================================
// 应用主入口
// ============================================================
const APP = {
    /**
     * 应用初始化
     */
    async init() {
        console.log('[app] AgentDojo 数据流追踪控制台启动中...');

        // 显示加载状态
        this._showLoading();

        // 各模块独立初始化，避免某个模块（例如 D3 加载失败）导致整个页面不可用
        const failures = [];
        const initModule = (name, fn) => {
            try {
                fn();
            } catch (err) {
                failures.push(name);
                console.error(`[app] ${name} 初始化失败:`, err);
            }
        };

        initModule('GRAPH', () => GRAPH.init());
        initModule('TIMELINE', () => TIMELINE.init());
        initModule('RISK_PANEL', () => RISK_PANEL.init());
        initModule('STATUS_PANEL', () => STATUS_PANEL.init());
        initModule('TRACE_PANEL', () => TRACE_PANEL.init());
        initModule('STORAGE_VIEW', () => STORAGE_VIEW.init());

        // 视图交互与模块无关，必须绑定
        this._initTabs();
        this._initModal();
        this._initResetButton();
        this._initFloatPanel();

        try {
            await CONSOLE.init();
        } catch (err) {
            failures.push('CONSOLE');
            console.error('[app] CONSOLE 初始化失败:', err);
        }

        try {
            await GRAPH.loadData();
            Store.set('lastNodeCount', GRAPH.nodes.length);
            Store.set('lastEdgeCount', GRAPH.links.length);
        } catch (err) {
            failures.push('GRAPH_DATA');
            console.error('[app] 加载图谱数据失败:', err);
            if (!GRAPH.simulation) {
                this._showError('图谱数据加载失败：D3 或后端服务不可用，可视化图谱暂不可用。');
            }
        }

        Store.set('loading', false);
        this._hideLoading();

        if (GRAPH.simulation) {
            this._startPolling();
        }

        console.log('[app] 可视化平台启动完成', failures.length > 0 ? `(部分模块失败: ${failures.join(', ')})` : '');
    },

    /**
     * 显示加载状态
     */
    _showLoading() {
        const container = document.getElementById('graph-container');
        if (!container) return;
        
        const loadingEl = document.createElement('div');
        loadingEl.className = 'loading-overlay';
        loadingEl.id = 'loadingOverlay';
        loadingEl.innerHTML = `
            <div class="loading-spinner"></div>
            <div class="loading-text">正在加载图谱数据...</div>
        `;
        container.appendChild(loadingEl);
    },

    /**
     * 隐藏加载状态
     */
    _hideLoading() {
        const loadingEl = document.getElementById('loadingOverlay');
        if (loadingEl) {
            loadingEl.style.opacity = '0';
            setTimeout(() => loadingEl.remove(), 500);
        }
    },

    /**
     * 显示错误信息
     */
    _showError(message) {
        const container = document.getElementById('graph-container');
        if (!container) return;
        
        const errorEl = document.createElement('div');
        errorEl.className = 'error-overlay';
        errorEl.innerHTML = `
            <div class="error-text">${message}</div>
            <button type="button" class="error-retry">重试</button>
        `;
        errorEl.querySelector('.error-retry').addEventListener('click', () => APP.init());
        container.appendChild(errorEl);
    },

    /**
     * 初始化导航标签切换
     */
    _initTabs() {
        const tabs = document.querySelectorAll('.tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // 切换标签激活状态
                tabs.forEach(t => {
                    t.classList.remove('active');
                    t.removeAttribute('aria-current');
                });
                tab.classList.add('active');
                tab.setAttribute('aria-current', 'page');
                
                // 切换视图模式
                const tabName = tab.dataset.tab;
                this._switchView(tabName);
            });
        });
    },

    /**
     * 切换视图模式
     */
    _switchView(tabName) {
        const graphPanel = document.querySelector('.graph-panel');
        const sidePanel = document.querySelector('.side-panel');
        const timelinePanel = document.querySelector('.timeline-panel');
        const mainContainer = document.querySelector('.main-container');
        const storageView = document.getElementById('storageView');

        if (tabName === 'storage') {
            if (mainContainer) mainContainer.style.display = 'none';
            if (timelinePanel) timelinePanel.style.display = 'none';
            if (storageView) storageView.hidden = false;
            document.getElementById('statusText').textContent = '存储';
            document.querySelector('.status-dot').className = 'status-dot';
            const hp = document.getElementById('historyListPanel');
            if (hp) hp.classList.remove('visible');
            if (typeof STORAGE_VIEW !== 'undefined') STORAGE_VIEW.activate();
            return;
        }

        if (storageView) storageView.hidden = true;
        if (typeof STORAGE_VIEW !== 'undefined') STORAGE_VIEW.deactivate();
        if (mainContainer) mainContainer.style.display = 'flex';

        switch (tabName) {
            case 'monitor':
                // 实时监控：显示所有面板
                graphPanel.style.display = 'flex';
                sidePanel.style.display = 'flex';
                timelinePanel.style.display = 'flex';
                if (Store.get('replaying')) {
                    this.exitReplay();
                } else {
                    document.getElementById('statusText').textContent = '实时';
                    document.querySelector('.status-dot').className = 'status-dot live';
                }
                break;
                
            case 'history':
                // 历史回放：放大拓扑图，隐藏风险卡片
                graphPanel.style.display = 'flex';
                sidePanel.style.display = 'flex';
                timelinePanel.style.display = 'flex';
                if (!Store.get('replaying')) {
                    document.getElementById('statusText').textContent = '回放';
                }
                document.querySelector('.status-dot').className = 'status-dot';
                break;
                
            case 'audit':
                // 风险审计：放大风险卡片，缩小拓扑图
                graphPanel.style.display = 'flex';
                sidePanel.style.display = 'flex';
                timelinePanel.style.display = 'none';
                document.getElementById('statusText').textContent = '审计';
                document.querySelector('.status-dot').className = 'status-dot';
                // 滚动到风险卡片区域
                document.querySelector('.risk-card-panel').scrollIntoView({ behavior: 'smooth' });
                break;
        }
        
        // 触发窗口大小变化事件，让 D3 重新计算布局
        window.dispatchEvent(new Event('resize'));
        const historyPanel = document.getElementById('historyListPanel');
        if (tabName !== 'history' && historyPanel) historyPanel.classList.remove('visible');
        if (tabName === 'history') this._loadHistoryList();
        if (tabName === 'audit') this._renderAuditExport();
    },

    /**
     * 初始化节点详情弹窗
     */
    async _loadHistoryList() {
        const data = await API.getTraces();
        let panel = document.getElementById('historyListPanel');

        if (!panel) {
            panel = document.createElement('div');
            panel.id = 'historyListPanel';
            panel.className = 'history-list';
            const graphPanel = document.querySelector('.graph-panel');
            if (graphPanel) graphPanel.appendChild(panel);
        }

        panel.innerHTML = '';

        const header = document.createElement('div');
        header.className = 'history-title';
        header.textContent = `历史记录 (${data ? data.total : 0})`;
        panel.appendChild(header);

        if (!data || !Array.isArray(data.traces) || data.traces.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'history-empty';
            empty.textContent = '暂无历史记录，执行指令后出现';
            panel.appendChild(empty);
        } else {
            for (const trace of data.traces) {
                const item = document.createElement('button');
                item.type = 'button';
                item.className = `history-item ${trace.blocked ? 'history-item-blocked' : 'history-item-ok'}`;
                item.dataset.traceId = trace.trace_id;

                const title = document.createElement('span');
                title.className = 'history-item-title';
                title.textContent = trace.prompt || trace.trace_id;

                const meta = document.createElement('span');
                meta.className = 'history-item-meta';
                meta.textContent = [
                    trace.timestamp,
                    trace.app_name,
                    trace.total_steps ? `${trace.total_steps} 步` : '',
                    trace.blocked ? '已阻断' : ''
                ].filter(Boolean).join(' | ');

                item.append(title, meta);
                panel.appendChild(item);
            }

            panel.querySelectorAll('.history-item').forEach((el) => {
                el.addEventListener('click', () => this._replayTrace(el.dataset.traceId));
            });
        }

        panel.classList.add('visible');
    },
    async _replayTrace(tid) {
        let trace;
        try {
            trace = await API.getTrace(tid);
        } catch (err) {
            console.error('[app] 加载历史记录失败:', err);
        }
        if (!trace) {
            this._showHistoryHint('历史记录加载失败，请刷新后重试');
            return;
        }

        const listPanel = document.getElementById('historyListPanel');
        if (listPanel) listPanel.classList.remove('visible');

        // 1. 拓扑图
        const graph = trace.graph && Array.isArray(trace.graph.nodes)
            ? trace.graph
            : null;
        const nodes = graph ? graph.nodes : [];
        const links = graph ? (graph.links || []) : [];
        if (!graph) {
            this._showHistoryHint('该历史记录未保存拓扑快照（旧版记录），仅显示事件与流转步骤');
        }
        GRAPH.setData(nodes, links, { suite: this._resolveTraceSuite(trace) });
        GRAPH.render();

        // 2. 执行时间线（合并生命周期步骤与真实事件内容）
        const events = Array.isArray(trace.events) ? trace.events : [];
        TIMELINE.setTrace(trace, 'top');

        // 3. 风险卡片与统计概览（使用历史快照，而不是实时数据）
        const riskCards = this._buildReplayRiskCards(trace);
        RISK_PANEL.render(riskCards);

        const summary = trace.graph_summary || {};
        const nodeCount = Number.isFinite(summary.total_nodes) ? summary.total_nodes : nodes.length;
        const edgeCount = Number.isFinite(summary.total_edges) ? summary.total_edges : links.length;
        GRAPH.updateStats(
            { total_nodes: nodeCount, total_edges: edgeCount },
            riskCards.length,
            events.length
        );
        STATUS_PANEL.setGraphStats(nodeCount, edgeCount);
        Store.set('lastNodeCount', nodeCount);
        Store.set('lastEdgeCount', edgeCount);

        // 4. 进入回放模式：暂停实时轮询，避免快照被覆盖
        this._enterReplayMode(trace);
    },

    /**
     * 解析历史记录所属 suite（新版记录使用 suite 字段，旧记录退回 app_name）。
     */
    _resolveTraceSuite(trace) {
        if (!trace) return null;
        const suite = trace.suite || trace.app_name || '';
        return ['banking', 'workspace', 'slack', 'travel'].includes(suite) ? suite : null;
    },

    /**
     * 从历史记录中恢复风险卡片。
     * 新版记录直接带有 risk_cards；旧版记录退化为从风险事件推导。
     */
    _buildReplayRiskCards(trace) {
        if (Array.isArray(trace.risk_cards) && trace.risk_cards.length > 0) {
            return trace.risk_cards;
        }

        const events = Array.isArray(trace.events) ? trace.events : [];
        const riskEvents = events.filter(e => e && e.type === 'risk');
        if (riskEvents.length === 0) return [];

        const ringTitles = {
            0: 'Ring 0: 安全事件',
            1: 'Ring 1: 提示注入检测',
            2: 'Ring 2: 意图一致性检查',
            3: 'Ring 3: 数据过度暴露缓解',
        };
        const actions = { 0: '阻断', 1: '阻断', 2: '阻断', 3: '脱敏' };

        return riskEvents.map((event) => {
            const ring = Number.isFinite(event.ring) ? event.ring : 0;
            const title = ringTitles[ring] || `Ring ${ring}: 安全事件`;
            const detail = event.block_reason || event.content || '检测到风险事件';
            const suite = this._resolveTraceSuite(trace);
            return {
                ring,
                title,
                detail,
                agent: event.agent_id || 'unknown',
                action: event.tool_intent || 'unknown',
                app: this._canonicalAppName(event.target_app, suite) || 'unknown',
                defense_ring: title,
                defense_action: actions[ring] || '阻断',
                defense_detail: detail,
                defense_effect: '已由防御系统处理',
            };
        });
    },

    /**
     * 兼容旧 trace 的模块级 APP 名。
     */
    _canonicalAppName(app, suite) {
        const raw = String(app || '').trim();
        if (!raw || raw === 'unknown') return raw || 'unknown';
        if (['system', 'banking', 'workspace', 'slack', 'travel'].includes(raw)) return raw;

        const moduleSuites = {
            'banking': 'banking',
            'banking_client': 'banking',
            'file_reader': 'banking',
            'user_account': 'banking',
            'travel': 'travel',
            'travel_booking_client': 'travel',
        };
        if (moduleSuites[raw]) return moduleSuites[raw];
        if (['email', 'email_client', 'calendar', 'calendar_client'].includes(raw)) {
            return suite || 'unified';
        }
        if (['cloud_drive', 'cloud_drive_client'].includes(raw)) return 'workspace';
        if (['slack', 'web'].includes(raw)) return 'slack';
        return raw;
    },

    /**
     * 进入历史回放状态
     */
    _enterReplayMode(trace) {
        Store.set('replaying', true);

        const statusText = document.getElementById('statusText');
        if (statusText) {
            statusText.textContent = trace.timestamp ? `回放 ${trace.timestamp}` : '回放';
        }

        const dot = document.querySelector('.status-dot');
        if (dot) {
            dot.className = 'status-dot';
            dot.title = '正在查看历史记录，点击“实时监控”返回实时数据';
        }
    },

    /**
     * 退出历史回放，恢复实时数据（默认重新加载实时快照）
     */
    exitReplay(options = {}) {
        const { reload = true } = options;
        if (!Store.get('replaying')) return;

        Store.set('replaying', false);
        TIMELINE.clear();

        const statusText = document.getElementById('statusText');
        if (statusText) statusText.textContent = '实时';

        const dot = document.querySelector('.status-dot');
        if (dot) {
            dot.className = 'status-dot live';
            dot.removeAttribute('title');
        }

        if (reload) {
            this._reloadLiveData();
        }
    },

    /**
     * 重新加载实时图谱、统计与状态
     */
    async _reloadLiveData() {
        try {
            await GRAPH.loadData();
            STATUS_PANEL.refresh();
        } catch (err) {
            console.error('[app] 恢复实时数据失败:', err);
        }
    },

    _showHistoryHint(msg) {
        const g = document.querySelector('.graph-panel');
        if (!g) return;
        const el = document.createElement('div');
        el.className = 'graph-hint';
        el.textContent = msg;
        g.appendChild(el);
        setTimeout(() => el.remove(), 4000);
    },
    _renderAuditExport() {
        let p = document.getElementById('auditExportPanel');
        const riskPanel = document.querySelector('.risk-card-panel');
        if (!riskPanel) return;

        if (!p) {
            p = document.createElement('div');
            p.id = 'auditExportPanel';
            p.className = 'audit-export';
            riskPanel.insertBefore(p, riskPanel.firstChild);
        }

        p.innerHTML = '';
        const exportBtn = document.createElement('button');
        exportBtn.type = 'button';
        exportBtn.className = 'btn-execute';
        exportBtn.textContent = '导出最新 Trace';
        exportBtn.addEventListener('click', () => this._exportLatestTrace());

        const label = document.createElement('span');
        label.className = 'audit-export-label';
        label.textContent = '审计模式';

        p.append(exportBtn, label);
    },

    async _exportLatestTrace() {
        try {
            const data = await API.getTraces();
            const latest = data && Array.isArray(data.traces) && data.traces.length > 0
                ? data.traces[0]
                : null;
            if (!latest) {
                alert('暂无可导出的历史记录');
                return;
            }
            const trace = await API.getTrace(latest.trace_id);
            if (!trace) {
                alert('Trace 数据加载失败');
                return;
            }
            const blob = new Blob([JSON.stringify(trace, null, 2)], { type: 'application/json' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = `${latest.trace_id}.json`;
            link.click();
            URL.revokeObjectURL(link.href);
        } catch (err) {
            console.error('[app] 导出 Trace 失败:', err);
            alert('导出失败，请稍后重试');
        }
    },

    _initModal() {
        const modal = document.getElementById('nodeModal');
        const closeBtn = modal.querySelector('.modal-close');
        
        closeBtn.addEventListener('click', () => {
            modal.classList.remove('show');
        });
        
        window.addEventListener('click', (event) => {
            if (event.target === modal) {
                modal.classList.remove('show');
            }
        });
    },

    /**
     * 初始化节点详情浮动面板的交互
     */
    _initFloatPanel() {
        const panel = document.getElementById('nodeDetailPanel');
        if (!panel) return;
        
        // 关闭按钮
        const closeBtn = document.getElementById('btnCloseNodeDetail');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                panel.style.display = 'none';
            });
        }
        
        // 最小化按钮
        const minimizeBtn = document.getElementById('btnMinimizeNodeDetail');
        if (minimizeBtn) {
            minimizeBtn.addEventListener('click', () => {
                panel.classList.toggle('minimized');
                minimizeBtn.setAttribute(
                    'aria-label',
                    panel.classList.contains('minimized') ? '展开' : '最小化'
                );
                minimizeBtn.setAttribute(
                    'title',
                    panel.classList.contains('minimized') ? '展开' : '最小化'
                );
            });
        }
        
        // 拖动功能
        const dragHandle = document.getElementById('nodeDetailDragHandle');
        if (dragHandle) {
            let isDragging = false;
            let startX, startY, origX, origY;
            
            dragHandle.addEventListener('mousedown', (e) => {
                // 如果点击的是按钮，不触发拖动
                if (e.target.closest('.float-panel-btn')) return;
                
                isDragging = true;
                const rect = panel.getBoundingClientRect();
                startX = e.clientX;
                startY = e.clientY;
                origX = rect.left;
                origY = rect.top;
                
                // 将 position 改为 fixed 以便自由拖动
                panel.style.position = 'fixed';
                panel.style.left = origX + 'px';
                panel.style.top = origY + 'px';
                panel.style.right = 'auto';
                
                e.preventDefault();
            });
            
            document.addEventListener('mousemove', (e) => {
                if (!isDragging) return;
                
                const dx = e.clientX - startX;
                const dy = e.clientY - startY;
                
                panel.style.left = (origX + dx) + 'px';
                panel.style.top = (origY + dy) + 'px';
            });
            
            document.addEventListener('mouseup', () => {
                isDragging = false;
            });
        }
    },

    /**
     * 初始化重置按钮
     */
    _initResetButton() {
        // 在控制台添加重置按钮
        const consoleCard = document.querySelector('.console-card');
        if (consoleCard) {
            const resetBtn = document.createElement('button');
            resetBtn.className = 'btn-execute btn-danger btn-block';
            resetBtn.textContent = '重置所有数据';
            resetBtn.addEventListener('click', async () => {
                if (confirm('确定要重置所有数据吗？')) {
                    if (Store.get('replaying')) this.exitReplay({ reload: false });
                    await API.resetData();
                    await GRAPH.loadData();
                    TIMELINE.clear();
                    RISK_PANEL.loadRiskCards();
                    Store.set('lastNodeCount', 0);
                    Store.set('lastEdgeCount', 0);
                    // 重置后重新加载场景列表
                    await CONSOLE.loadScenarios();
                    if (typeof STORAGE_VIEW !== 'undefined') STORAGE_VIEW.notifyDataChanged();
                }
            });
            consoleCard.appendChild(resetBtn);
        }
    },

    /**
     * 显示节点详情弹窗（增强版）
     */
    showNodeModal(nodeDetail) {
        const modal = document.getElementById('nodeModal');
        const body = document.getElementById('modalBody');
        
        if (!nodeDetail) {
            body.innerHTML = '<p>无法获取节点详情</p>';
            modal.classList.add('show');
            return;
        }
        
        const typeLabels = {
            'AIAgent': 'AI 智能体',
            'AIModelInvocation': 'LLM 推理',
            'AgentTool': '工具调用',
            'Prompt': '提示内容',
            'DomainData': '数据实体',
        };

        // 角色标签映射
        const roleLabels = {
            'input': { label: '输入参数', color: 'var(--accent-blue)' },
            'output': { label: '输出结果', color: 'var(--accent-green)' },
            'created': { label: '环境变更 - 创建', color: 'var(--accent-orange)' },
            'updated': { label: '环境变更 - 更新', color: 'var(--accent-yellow)' },
        };

        let html = `
            <h2>
                ${typeLabels[nodeDetail.type] || nodeDetail.type}: ${nodeDetail.label || nodeDetail.id}
            </h2>
            <div class="detail-field">
                <span class="label">ID</span>
                <div class="value">${nodeDetail.id}</div>
            </div>
            <div class="detail-field">
                <span class="label">类型</span>
                <div class="value">${typeLabels[nodeDetail.type] || nodeDetail.type}</div>
            </div>
        `;

        // DomainData 显示角色
        if (nodeDetail.type === 'DomainData' && nodeDetail.operation) {
            const role = roleLabels[nodeDetail.operation] || { label: '数据', color: 'var(--text-primary)' };
            html += `
                <div class="detail-field">
                    <span class="label">角色</span>
                    <div class="value" style="color:${role.color};font-weight:600;">${role.label}</div>
                </div>
            `;
        }

        // 输出结果节点不显示名称
        if (!(nodeDetail.type === 'DomainData' && nodeDetail.operation === 'output')) {
            html += `
                <div class="detail-field">
                    <span class="label">名称</span>
                    <div class="value">${nodeDetail.label || nodeDetail.id}</div>
                </div>
            `;
        }

        if (nodeDetail.app) {
            const appLabels = {
                'system': '系统',
                'banking': '银行',
                'workspace': '办公',
                'slack': '通讯',
                'travel': '旅行',
                'unified': '统一',
            };
            html += `
                <div class="detail-field">
                    <span class="label">APP 域</span>
                    <div class="value">${appLabels[nodeDetail.app] || nodeDetail.app}</div>
                </div>
            `;
            if (nodeDetail.module) {
                html += `
                    <div class="detail-field">
                        <span class="label">工具模块</span>
                        <div class="value">${nodeDetail.module}</div>
                    </div>
                `;
            }
        }

        if (nodeDetail.is_sensitive) {
            html += `
                <div class="detail-field">
                    <span class="label">敏感数据</span>
                    <div class="value" style="color:var(--accent-red);font-weight:600;">包含敏感信息</div>
                </div>
            `;
        }

        if (nodeDetail.blocked) {
            html += `
                <div class="detail-field">
                    <span class="label">阻断状态</span>
                    <div class="value blocked">已阻断</div>
                </div>
                <div class="detail-field">
                    <span class="label">阻断原因</span>
                    <div class="value blocked">${nodeDetail.block_reason || '未知'}</div>
                </div>
            `;
        }

        if (nodeDetail.inputs) {
            html += `
                <div class="detail-field">
                    <span class="label">输入参数</span>
                    <div class="value detail-value-long">${nodeDetail.inputs}</div>
                </div>
            `;
        }

        if (nodeDetail.content) {
            html += `
                <div class="detail-field">
                    <span class="label">内容</span>
                    <div class="value">${nodeDetail.content}</div>
                </div>
            `;
        }

        if (nodeDetail.prompt) {
            html += `
                <div class="detail-field">
                    <span class="label">Prompt</span>
                    <div class="value detail-value-long">
                        ${nodeDetail.prompt.substring(0, 200)}${nodeDetail.prompt.length > 200 ? '...' : ''}
                    </div>
                </div>
            `;
        }

        if (nodeDetail.response) {
            html += `
                <div class="detail-field">
                    <span class="label">LLM 响应</span>
                    <div class="value detail-value-long">
                        ${nodeDetail.response.substring(0, 200)}${nodeDetail.response.length > 200 ? '...' : ''}
                    </div>
                </div>
            `;
        }

        body.innerHTML = html;
        modal.classList.add('show');
    },

    /**
     * 启动定时轮询（增量更新检测）
     */
    _startPolling() {
        if (Store.get('isPolling')) return;
        Store.set('isPolling', true);
        
        // 每 5 秒检查一次新数据
        setInterval(async () => {
            try {
                // 历史回放期间暂停实时增量刷新，避免覆盖回放快照
                if (Store.get('replaying')) return;

                const data = await API.getGraphData();
                if (data && data.graph) {
                    const newNodeCount = data.graph.nodes.length;
                    const newEdgeCount = data.graph.links.length;
                    const oldNodeCount = Store.get('lastNodeCount');
                    const oldEdgeCount = Store.get('lastEdgeCount');
                    
                    // 增量更新检测：只在新数据有变化时更新
                    if (newNodeCount !== oldNodeCount || newEdgeCount !== oldEdgeCount) {
                        console.log(`[graph] 检测到新数据: +${newNodeCount - oldNodeCount} 节点, +${newEdgeCount - oldEdgeCount} 边`);
                        
                        // 使用 setData 确保引用一致性
                        GRAPH.setData(data.graph.nodes, data.graph.links, { suite: data.suite || null });
                        GRAPH.render();
                        
                        Store.set('lastNodeCount', newNodeCount);
                        Store.set('lastEdgeCount', newEdgeCount);
                        
                        if (data.events) {
                            TIMELINE.loadEvents(data.events);
                        }
                        
                        const riskCards = await RISK_PANEL.loadRiskCards();
                        GRAPH.updateStats(
                            data.summary,
                            Array.isArray(riskCards) ? riskCards.length : 0,
                            Array.isArray(data.events) ? data.events.length : undefined
                        );
                    }
                }
            } catch (err) {
                // 静默处理轮询错误
            }
        }, 5000);
    }
};

// ============================================================
// 页面加载完成后启动应用
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    APP.init();
});
