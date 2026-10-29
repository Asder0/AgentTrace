/**
 * 主入口模块 - AgentDojo 数据流追踪可视化平台
 * 
 * 初始化所有模块，协调数据加载和页面交互。
 * 
 * 增强功能：
 * - 统一状态管理（Store）
 * - 优化轮询逻辑（增量更新检测）
 * - 加载状态管理
 * - 错误边界处理
 */

// ============================================================
// 全局状态管理
// ============================================================
const Store = {
    _state: {
        lastNodeCount: 0,
        lastEdgeCount: 0,
        isPolling: false,
        replaying: false,
    },
    
    get(key) {
        return this._state[key];
    },
    
    set(key, value) {
        this._state[key] = value;
    },
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
        initModule('STORAGE_VIEW', () => STORAGE_VIEW.init());

        // 视图交互与模块无关，必须绑定
        this._initTabs();
        this._initResetButton();
        this._initFloatPanel();
        this._initSidePanelResizer();
        this._initL2ConfirmationPolling();

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

        this._hideLoading();

        if (GRAPH.simulation) {
            this._startPolling();
        }

        console.log('[app] 可视化平台启动完成', failures.length > 0 ? `(部分模块失败: ${failures.join(', ')})` : '');
    },

    /**
     * 显示加载状态
     */
    _initSidePanelResizer() {
        const panel = document.querySelector('.side-panel');
        const handle = document.getElementById('sideResizer');
        const container = document.querySelector('.main-container');
        if (!panel || !handle || !container) return;

        this._sidePanel = panel;
        this._sideResizer = handle;
        this._mainContainer = container;
        this._sidePanelWidthKey = 'agentdojo.sidePanelWidth';
        this._sidePanelCollapsedKey = 'agentdojo.sidePanelCollapsed';
        this._sidePanelRestoreWidth = 360;

        const savedWidth = this._readSidePanelNumber(this._sidePanelWidthKey, 360);
        this._sidePanelRestoreWidth = savedWidth;
        this._applySidePanelWidth(savedWidth, false);
        this._setSidePanelCollapsed(
            this._readSidePanelNumber(this._sidePanelCollapsedKey, 0) === 1,
            false
        );

        handle.addEventListener('pointerdown', (ev) => this._startSidePanelResize(ev));
        handle.addEventListener('dblclick', () => {
            this._setSidePanelCollapsed(!panel.classList.contains('collapsed'));
        });
        handle.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' || ev.key === ' ') {
                ev.preventDefault();
                this._setSidePanelCollapsed(!panel.classList.contains('collapsed'));
                return;
            }
            const step = ev.shiftKey ? 48 : 16;
            const current = panel.classList.contains('collapsed')
                ? 0
                : panel.getBoundingClientRect().width;
            if (ev.key === 'ArrowLeft') {
                ev.preventDefault();
                this._setSidePanelCollapsed(false);
                this._applySidePanelWidth(current + step);
            } else if (ev.key === 'ArrowRight') {
                ev.preventDefault();
                this._applySidePanelWidth(current - step);
            } else if (ev.key === 'Home') {
                ev.preventDefault();
                this._setSidePanelCollapsed(true);
            } else if (ev.key === 'End') {
                ev.preventDefault();
                this._setSidePanelCollapsed(false);
                this._applySidePanelWidth(this._maxSidePanelWidth());
            }
        });
    },

    _startSidePanelResize(ev) {
        if (typeof ev.button === 'number' && ev.button !== 0) return;
        ev.preventDefault();
        if (this._sidePanel.classList.contains('collapsed')) {
            this._setSidePanelCollapsed(false, false);
        }
        this._sideResizeState = {
            startX: ev.clientX,
            startWidth: this._sidePanel.getBoundingClientRect().width,
        };
        document.body.classList.add('resizing-side');
        this._onSidePointerMove = this._onSidePointerMove || ((event) => {
            if (!this._sideResizeState) return;
            const width = this._sideResizeState.startWidth
                + (this._sideResizeState.startX - event.clientX);
            if (width <= 64) {
                this._setSidePanelCollapsed(true, false);
                return;
            }
            this._applySidePanelWidth(width, false);
        });
        this._onSidePointerUp = this._onSidePointerUp || (() => {
            if (!this._sideResizeState) return;
            window.removeEventListener('pointermove', this._onSidePointerMove);
            window.removeEventListener('pointerup', this._onSidePointerUp);
            window.removeEventListener('pointercancel', this._onSidePointerUp);
            this._sideResizeState = null;
            document.body.classList.remove('resizing-side');
            if (this._sidePanel.classList.contains('collapsed')) {
                this._storeSidePanelNumber(this._sidePanelCollapsedKey, 1);
            } else {
                this._storeSidePanelNumber(
                    this._sidePanelWidthKey,
                    this._sidePanel.getBoundingClientRect().width
                );
                this._storeSidePanelNumber(this._sidePanelCollapsedKey, 0);
            }
            window.dispatchEvent(new Event('resize'));
        });
        window.addEventListener('pointermove', this._onSidePointerMove);
        window.addEventListener('pointerup', this._onSidePointerUp);
        window.addEventListener('pointercancel', this._onSidePointerUp);
        if (this._sideResizer.setPointerCapture) {
            try {
                this._sideResizer.setPointerCapture(ev.pointerId);
            } catch (err) {
                // Window-level listeners still complete the resize.
            }
        }
    },

    _setSidePanelCollapsed(collapsed, persist = true) {
        if (!this._sidePanel || !this._sideResizer) return;
        const next = !!collapsed;
        if (next && !this._sidePanel.classList.contains('collapsed')) {
            this._sidePanelRestoreWidth = this._sidePanel.getBoundingClientRect().width;
        }
        this._sidePanel.classList.toggle('collapsed', next);
        this._sideResizer.classList.toggle('is-collapsed', next);
        this._sideResizer.title = next
            ? '点击展开右侧信息栏'
            : '拖动调整宽度；拖到最右侧或双击可折叠';
        if (!next && this._sidePanelRestoreWidth) {
            this._applySidePanelWidth(this._sidePanelRestoreWidth, false);
        }
        if (persist) {
            this._storeSidePanelNumber(this._sidePanelCollapsedKey, next ? 1 : 0);
            if (!next) {
                this._storeSidePanelNumber(
                    this._sidePanelWidthKey,
                    this._sidePanelRestoreWidth
                );
            }
            window.dispatchEvent(new Event('resize'));
        }
    },

    _applySidePanelWidth(width, persist = true) {
        if (!this._sidePanel) return;
        const min = 220;
        const max = this._maxSidePanelWidth();
        const value = Math.max(min, Math.min(max, Math.round(Number(width) || 360)));
        this._sidePanel.style.width = `${value}px`;
        this._sidePanel.classList.remove('collapsed');
        this._sideResizer.classList.remove('is-collapsed');
        if (persist) {
            this._storeSidePanelNumber(this._sidePanelWidthKey, value);
        }
    },

    _maxSidePanelWidth() {
        const width = this._mainContainer
            ? this._mainContainer.getBoundingClientRect().width
            : window.innerWidth;
        return Math.max(300, Math.min(640, width * 0.55));
    },

    _readSidePanelNumber(key, fallback) {
        try {
            const raw = window.localStorage.getItem(key);
            if (raw == null || raw === '') return fallback;
            const value = Number(raw);
            return Number.isFinite(value) ? value : fallback;
        } catch (err) {
            return fallback;
        }
    },

    _storeSidePanelNumber(key, value) {
        try {
            window.localStorage.setItem(key, String(value));
        } catch (err) {
            // Ignore storage failures.
        }
    },

    _initL2ConfirmationPolling() {
        const overlay = document.getElementById('l2ConfirmationOverlay');
        if (!overlay) return;
        this._confirmationOverlay = overlay;
        this._activeConfirmationId = null;
        this._confirmationResolving = false;

        const approve = document.getElementById('btnApproveL2');
        const reject = document.getElementById('btnRejectL2');
        const focusGraph = document.getElementById('btnFocusL2Graph');
        if (approve) {
            approve.addEventListener('click', () => this._resolveL2Confirmation(true));
        }
        if (reject) {
            reject.addEventListener('click', () => this._resolveL2Confirmation(false));
        }
        if (focusGraph) {
            focusGraph.addEventListener('click', () => {
                if (
                    this._activeConfirmationRequest
                    && typeof GRAPH !== 'undefined'
                ) {
                    GRAPH.focusConfirmationEvidence(
                        this._activeConfirmationRequest
                    );
                }
            });
        }

        const poll = async () => {
            if (this._confirmationResolving || document.hidden) return;
            try {
                const pending = await API.getPendingConfirmations();
                this._renderL2Confirmation(
                    Array.isArray(pending) && pending.length ? pending[0] : null
                );
            } catch (err) {
                // The execution endpoint can be starting while polling begins.
            }
        };
        poll();
        this._confirmationTimer = setInterval(poll, 1000);
    },

    _renderL2Confirmation(request) {
        const overlay = this._confirmationOverlay;
        if (!overlay) return;
        if (!request) {
            overlay.hidden = true;
            overlay.classList.remove('reviewing-graph');
            document.body.classList.remove('l2-review-active');
            this._activeConfirmationId = null;
            this._activeConfirmationRequest = null;
            return;
        }
        const isNewRequest = this._activeConfirmationId !== request.request_id;
        this._activeConfirmationId = request.request_id;
        this._activeConfirmationRequest = request;
        overlay.hidden = false;
        overlay.classList.add('reviewing-graph');
        document.body.classList.add('l2-review-active');
        const chain = request.chain_check || {};
        const riskLabels = window.AgentTraceRiskLabels || {};
        const setText = (id, value) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value == null ? '-' : String(value);
        };
        setText('l2ConfirmationTitle', `${request.tool_name} 需要确认`);
        setText('l2ConfirmationReason', chain.reason || '调用链检查通过，等待用户确认。');
        setText(
            'l2ConfirmationChain',
            (chain.evidence || []).join(' → ') || '调用链证据已记录在任务计划中。'
        );
        const flow = request.flow_check || {};
        const destinationLabels = {
            fixed_authorized: '固定授权接收方',
            derived_authorized: '受控派生接收方',
            unauthorized: '未授权接收方',
        };
        setText(
            'l2ConfirmationFlow',
            [
                `接收方：${destinationLabels[flow.destination_state] || flow.destination_state || '未检查'}`,
                `外发等级：${flow.confidentiality || '-'} / ${flow.max_confidentiality || '-'}`,
                `来源完整性：${flow.provenance_state === 'unknown' ? '未知' : '已声明'}`,
                `数据来源：${(flow.data_sources || []).join(', ') || '用户输入'}`,
                `来源提示：${(flow.provenance_warnings || []).join(', ') || '无'}`,
            ].join(' · ')
        );
        setText('l2ConfirmationTitle', `${request.tool_name} 需要确认`);
        setText(
            'l2ConfirmationReason',
            riskLabels.confirmationReason
                ? riskLabels.confirmationReason(request)
                : '该操作属于计划内 L2 动作，请人工确认后执行。'
        );
        setText(
            'l2ConfirmationChain',
            riskLabels.confirmationSummary
                ? riskLabels.confirmationSummary(request)
                : '调用链检查已完成，证据已记录在任务计划中。'
        );
        const localizedDestinationLabels = {
            fixed_authorized: '固定授权接收方',
            derived_authorized: '受控派生接收方',
            unauthorized: '未授权接收方',
        };
        setText(
            'l2ConfirmationFlow',
            [
                `接收方：${(flow.destinations || []).join(', ') || '-'}`,
                `接收方状态：${
                    localizedDestinationLabels[flow.destination_state]
                    || '未检查'
                }`,
                `敏感等级：${
                    riskLabels.confidentialityLabel
                        ? riskLabels.confidentialityLabel(flow.confidentiality)
                        : flow.confidentiality || '-'
                } / 上限 ${
                    riskLabels.confidentialityLabel
                        ? riskLabels.confidentialityLabel(flow.max_confidentiality)
                        : flow.max_confidentiality || '-'
                }`,
                `来源完整性：${
                    riskLabels.provenanceStateLabel
                        ? riskLabels.provenanceStateLabel(flow.provenance_state)
                        : flow.provenance_state || '未知'
                }`,
                `数据来源：${(flow.data_sources || []).join(', ') || '用户输入'}`,
                `来源祖先：${(flow.provenance_ancestors || []).join(', ') || '-'}`,
                `来源提醒：${
                    (flow.provenance_warnings || [])
                        .map(item => riskLabels.warningLabel
                            ? riskLabels.warningLabel(item)
                            : '来源校验存在提醒')
                        .join('；') || '无'
                }`,
            ].join(' · ')
        );
        setText('l2ConfirmationTool', request.tool_name);
        setText(
            'l2ConfirmationApp',
            window.AgentTraceAppCatalog.appLabel(request.app || 'unknown')
        );
        setText(
            'l2ConfirmationPlan',
            [
                `${request.plan_id || '-'} / r${request.plan_revision || '?'}`,
                request.plan_hash
                    ? `hash ${String(request.plan_hash).replace(/^sha256:/, '').slice(0, 16)}`
                    : '',
            ].filter(Boolean).join(' · ')
        );
        setText(
            'l2ConfirmationArgs',
            JSON.stringify(request.args || {}, null, 2)
        );
        this._renderL2Evidence(
            flow.field_sources || [],
            flow.parameter_generation || {},
            request.args || {}
        );
        if (isNewRequest && typeof GRAPH !== 'undefined') {
            GRAPH.loadData()
                .then(() => GRAPH.focusConfirmationEvidence(request))
                .catch(() => {});
        }
    },

    _renderL2Evidence(
        fieldSources,
        parameterGeneration = {},
        finalArgs = {}
    ) {
        const container = document.getElementById('l2ConfirmationEvidence');
        if (!container) return;
        const escape = value => String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        const safeRender = (value, limit = 0) => {
            let text = String(value == null ? '' : value).trim();
            if (limit > 0 && text.length > limit) {
                text = `${text.slice(0, limit)}…`;
            }
            if (window.AgentTraceContent?.render) {
                return window.AgentTraceContent.render(text);
            }
            return escape(text).replace(/\n/g, '<br>');
        };
        const sources = Array.isArray(fieldSources) ? fieldSources : [];
        const generationByParameter = parameterGeneration || {};
        const parameters = [];
        const addParameter = (name) => {
            const parameter = String(name || '').trim();
            if (parameter && !parameters.includes(parameter)) {
                parameters.push(parameter);
            }
        };
        Object.keys(finalArgs || {}).forEach(addParameter);
        Object.keys(generationByParameter).forEach(addParameter);
        sources.forEach(item => addParameter(item.parameter));

        if (parameters.length === 0) {
            container.innerHTML = `
                <div class="confirmation-evidence-title">外发参数与溯源证据</div>
                <div class="confirmation-evidence-item">
                    当前调用没有可展示的参数或字段级来源，请结合左侧执行链判断。
                </div>`;
            return;
        }

        const formatFinalValue = (value) => {
            if (typeof value === 'string') return value;
            try {
                return JSON.stringify(value, null, 2);
            } catch (err) {
                return String(value);
            }
        };
        const generationKindLabel = (kind) => {
            if (!kind) return '未记录';
            return window.AgentTraceRiskLabels?.generationKindLabel
                ? window.AgentTraceRiskLabels.generationKindLabel(kind)
                : kind;
        };
        const semanticLabel = (generation) => {
            if (generation.validation_mode === 'natural_language_manual') {
                return '自然语言内容，仅人工核对来源与风险';
            }
            if (typeof generation.semantic_supported !== 'boolean') {
                return '未记录';
            }
            return generation.semantic_supported
                ? '已在来源内容或动态键中定位'
                : '未直接定位，需核对语义推导';
        };

        container.innerHTML = `
            <div class="confirmation-evidence-title">
                外发参数、生成说明与来源证据（${parameters.length} 个参数）
            </div>
            ${parameters.map((parameter, parameterIndex) => {
                const generation = generationByParameter[parameter] || {};
                const parameterSources = sources.filter(
                    item => String(item.parameter || '') === parameter
                );
                const confidence = Number(generation.confidence);
                const confidenceLabel = (
                    generation.generation_kind === 'copy'
                        ? '控制器置信度'
                        : '模型自报置信度'
                );
                const finalValue = Object.prototype.hasOwnProperty.call(
                    finalArgs || {},
                    parameter
                ) ? formatFinalValue(finalArgs[parameter]) : '未记录';
                return `
                    <div class="confirmation-parameter-card">
                        <div class="confirmation-parameter-header">
                            <span class="confirmation-parameter-name">
                                ${parameterIndex + 1}. ${escape(parameter)}
                            </span>
                            <span class="confirmation-parameter-kind">
                                ${escape(generationKindLabel(
                                    generation.generation_kind
                                ))}
                            </span>
                        </div>
                        <div class="confirmation-parameter-value">
                            <span>最终参数值</span>
                            <pre>${escape(finalValue)}</pre>
                        </div>
                        <div class="confirmation-parameter-meta">
                            <span>${escape(confidenceLabel)}：${
                                Number.isFinite(confidence)
                                    ? `${Math.round(confidence * 100)}%`
                                    : '未记录'
                            }</span>
                            <span>语义支持：${escape(
                                semanticLabel(generation)
                            )}</span>
                            <span>来源字段：${parameterSources.length}</span>
                        </div>
                        <div class="confirmation-parameter-explanation">
                            <div class="confirmation-evidence-meta">生成说明</div>
                            <div class="confirmation-parameter-explanation-text">
                                ${
                                    generation.explanation
                                        ? safeRender(generation.explanation)
                                        : '控制器未记录额外生成说明，请核对最终值。'
                                }
                            </div>
                        </div>
                        ${parameterSources.length > 0
                            ? parameterSources.map((item, sourceIndex) => {
                                const source = item.source
                                    || [
                                        item.app,
                                        item.entity,
                                    ].filter(Boolean).join(':')
                                    || '未知来源';
                                const action = item.source_action
                                    || '未知动作';
                                const path = item.source_path || '$';
                                const refId = item.ref_id
                                    || item.source_id
                                    || '';
                                const span = (
                                    item.start != null
                                    && item.end != null
                                ) ? ` · 字符区间 ${item.start}:${item.end}` : '';
                                const quote = String(
                                    item.extracted_text || ''
                                ).trim();
                                return `
                                    <div class="confirmation-evidence-item">
                                        <div class="confirmation-evidence-source">
                                            证据 ${sourceIndex + 1} · ${escape(source)}
                                            · ${escape(action)}
                                        </div>
                                        <div class="confirmation-evidence-meta">
                                            ${escape(path)}${escape(span)}
                                            ${refId ? ` · ${escape(refId)}` : ''}
                                        </div>
                                        ${quote ? `
                                            <div class="confirmation-evidence-quote">
                                                ${safeRender(quote, 360)}
                                            </div>` : ''}
                                    </div>`;
                            }).join('')
                            : `
                                <div class="confirmation-evidence-item">
                                    该参数没有字段级来源证据；若它是用户直接提供的
                                    固定参数，请核对上方最终值。
                                </div>`}
                    </div>`;
            }).join('')}`;
    },

    async _resolveL2Confirmation(approved) {
        if (!this._activeConfirmationId || this._confirmationResolving) return;
        this._confirmationResolving = true;
        const buttons = this._confirmationOverlay.querySelectorAll('button');
        buttons.forEach((button) => { button.disabled = true; });
        try {
            await API.resolveConfirmation(this._activeConfirmationId, approved);
            this._confirmationOverlay.hidden = true;
            this._confirmationOverlay.classList.remove('reviewing-graph');
            document.body.classList.remove('l2-review-active');
            this._activeConfirmationId = null;
            this._activeConfirmationRequest = null;
        } catch (err) {
            console.error('[confirmation] resolve failed', err);
        } finally {
            this._confirmationResolving = false;
            buttons.forEach((button) => { button.disabled = false; });
        }
    },

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
            document.getElementById('statusText').textContent = '环境变更';
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
                const taskState = String(
                    trace.task_outcome?.state || ''
                ).toUpperCase();
                const incomplete = taskState === 'INCOMPLETE';
                const item = document.createElement('button');
                item.type = 'button';
                item.className = `history-item ${
                    trace.blocked
                        ? 'history-item-blocked'
                        : incomplete
                            ? 'history-item-incomplete'
                            : 'history-item-ok'
                }`;
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
                    trace.blocked ? '已阻断' : '',
                    trace.has_environment_snapshots ? '含环境快照' : '',
                    incomplete ? '未完成' : ''
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
        this._repairTraceStepNodeIds(trace);

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
        if (typeof STORAGE_VIEW !== 'undefined') STORAGE_VIEW.setTrace(trace);

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

    _repairTraceStepNodeIds(trace) {
        const nodes = Array.isArray(trace?.graph?.nodes) ? trace.graph.nodes : [];
        const tools = nodes.filter(node => node.type === 'AgentTool');
        const byName = new Map();
        tools.forEach((node) => {
            const candidates = [
                node.label,
                node.tool_intent,
                node.tool_base_name,
                node.tool_alias,
            ];
            const id = String(node.id || '');
            if (id.startsWith('Activity_')) {
                const raw = id.slice('Activity_'.length);
                candidates.push(raw, raw.replace(/_[^_]+$/, ''));
            }
            candidates.filter(Boolean).forEach(name => {
                if (!byName.has(String(name))) byName.set(String(name), node);
            });
        });
        const findTool = (name) => {
            const value = String(name || '');
            const exact = byName.get(value);
            if (exact) return exact;
            if (value.includes('__')) {
                return byName.get(value.split('__').slice(1).join('__')) || null;
            }
            return null;
        };

        (trace.steps || []).forEach((step) => {
            if (step.nodeId) return;
            const match = String(step.name || '').match(/^工具调用[:：]\s*(.+)$/);
            const node = match ? findTool(match[1]) : null;
            if (node) {
                step.nodeId = node.id;
                step.nodeType = 'AgentTool';
            }
        });
        (trace.events || []).forEach((event) => {
            const toolName = event.tool_intent || '';
            const node = findTool(toolName);
            if (node && node.app) event.target_app = node.app;
        });
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
        const normalizeRisk = card => {
            const labels = window.AgentTraceRiskLabels;
            return labels ? labels.normalizeCard(card) : card;
        };
        const savedRisks = Array.isArray(trace.risk_cards)
            ? trace.risk_cards.map(normalizeRisk)
            : [];
        const savedPolicies = Array.isArray(trace.policy_events)
            ? trace.policy_events.map(event => ({
                ...event,
                event_kind: 'policy',
                title: event.title || `Ring ${event.ring || '?'}: 策略事件`,
                defense_detail: event.detail || event.reason || '策略事件',
            })).map(normalizeRisk)
            : [];
        if (savedRisks.length > 0 || savedPolicies.length > 0) {
            return [...savedRisks, ...savedPolicies];
        }

        const events = Array.isArray(trace.events) ? trace.events : [];
        const riskEvents = events.filter(
            e => e && ['risk', 'policy'].includes(e.type)
        );
        if (riskEvents.length === 0) return [];

        return riskEvents.flatMap((event) => {
            const detail = event.block_reason || event.content || '检测到风险事件';
            const suite = this._resolveTraceSuite(trace);
            const risks = Array.isArray(event.risks) && event.risks.length
                ? event.risks
                : Array.isArray(event.risk_assessments) && event.risk_assessments.length
                    ? event.risk_assessments
                    : Array.isArray(event.policy_events) && event.policy_events.length
                        ? event.policy_events
                        : [{}];
            return risks.map((risk) => normalizeRisk({
                ring: Number.isFinite(risk.ring) ? risk.ring : event.ring || 0,
                decision: risk.decision || 'ADVISORY',
                severity: risk.severity || 'medium',
                policy_id: risk.policy_id || '',
                detail: risk.reason || detail,
                defense_detail: risk.reason || detail,
                evidence_entity_ids: risk.evidence_entity_ids || [],
                source_ids: risk.source_ids || [],
                sink_ids: risk.sink_ids || [],
                fsm_before: risk.fsm_before || null,
                fsm_after: risk.fsm_after || null,
                agent: event.agent_id || 'unknown',
                action: event.tool_intent || 'unknown',
                app: this._canonicalAppName(event.target_app, suite) || 'unknown',
            }));
        });
    },

    /**
     * 兼容旧 trace 的模块级 APP 名。
     */
    _canonicalAppName(app, suite) {
        return window.AgentTraceAppCatalog.canonicalApp(app, suite);
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
        if (typeof STORAGE_VIEW !== 'undefined') STORAGE_VIEW.clearTrace();
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
