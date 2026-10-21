/**
 * 执行时间线模块 - 展示 Agent 一次执行的完整生命周期
 *
 * 数据来源：
 * - steps：用户输入 → API 请求 → 后端接收 → LLM 推理 → 工具调用 → 图谱更新
 * - events：每个步骤对应的真实 Prompt、推理内容与工具输出
 *
 * 两者按执行顺序合并为一条时间线：
 * - steps 提供完整阶段、执行状态和图谱节点关联
 * - events 补充完整的输入输出内容
 * - 仅有 events 时自动退化为事件流视图
 * - 支持拖拽 / 方向键调整面板高度，双击恢复默认高度
 */

const TIMELINE = {
    container: null,
    panel: null,

    /** 事件数据（LLM 推理 / 工具调用 / 风险） */
    events: [],

    /** 生命周期步骤数据 */
    steps: [],

    /** 当前 trace 所属 suite（用于兼容旧数据的模块级 APP 名） */
    _contextSuite: null,

    /** 当前筛选条件：all / phase / llm / tool / risk */
    _filter: 'all',

    /** 面板是否收起 */
    _collapsed: false,

    /** 最多保留的事件数，防止长时间运行后 DOM 过大 */
    _maxEvents: 500,

    /** 高度调整 */
    _resizer: null,
    _resizeState: null,
    _heightKey: 'agentdojo.timelineHeight',
    _defaultHeight: 300,
    _minHeightPx: 96,

    /**
     * 初始化时间线
     */
    init() {
        this.container = document.getElementById('timelineEvents');
        this.panel = document.querySelector('.timeline-panel');

        if (!this.container) {
            console.warn('时间线容器不存在');
            return;
        }

        this._bindControls();
        this._initResizer();
        this._showEmpty();
    },

    /**
     * 绑定筛选、收起、清空与展开事件
     */
    _bindControls() {
        const clearBtn = document.getElementById('btnClearTimeline');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clear());
        }

        const toggleBtn = document.getElementById('btnToggleTimeline');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleCollapsed());
        }

        const filters = document.getElementById('timelineFilters');
        if (filters) {
            filters.addEventListener('click', (ev) => {
                const btn = ev.target.closest('.timeline-filter');
                if (!btn) return;
                this._filter = btn.dataset.filter || 'all';
                filters.querySelectorAll('.timeline-filter').forEach((item) => {
                    const active = item === btn;
                    item.classList.toggle('active', active);
                    item.setAttribute('aria-pressed', active ? 'true' : 'false');
                });
                this._render('none');
            });
        }

        this.container.addEventListener('click', (ev) => {
            // 点击“图谱定位”时在拓扑图中高亮对应节点
            const nodeLink = ev.target.closest('.timeline-node-link');
            if (nodeLink) {
                const nodeId = nodeLink.dataset.nodeId;
                if (!nodeId || typeof GRAPH === 'undefined') return;
                if (GRAPH.flashNode) GRAPH.flashNode(nodeId);
                return;
            }

            // 展开/收起长内容
            const toggle = ev.target.closest('.timeline-toggle');
            if (!toggle) return;
            const card = toggle.closest('.timeline-event');
            if (!card) return;

            const expanded = card.classList.toggle('expanded');
            toggle.textContent = expanded ? '收起' : '展开';
            toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        });
    },

    /**
     * 收起 / 展开整个时间线面板
     */
    toggleCollapsed() {
        this._setCollapsed(!this._collapsed);
    },

    /**
     * 设置收起 / 展开状态
     */
    _setCollapsed(collapsed) {
        this._collapsed = !!collapsed;
        if (this.panel) {
            this.panel.classList.toggle('collapsed', this._collapsed);
        }
        const toggleBtn = document.getElementById('btnToggleTimeline');
        if (toggleBtn) {
            toggleBtn.textContent = this._collapsed ? '展开' : '收起';
        }
        this._updateResizerAria();
    },

    /**
     * 初始化高度调整手柄
     */
    _initResizer() {
        const handle = document.getElementById('timelineResizer');
        if (!handle || !this.panel) return;

        this._resizer = handle;

        const savedHeight = this._readSavedHeight();
        if (savedHeight) {
            this._applyHeight(savedHeight, false);
        }

        handle.addEventListener('pointerdown', (ev) => this._startResize(ev));
        handle.addEventListener('keydown', (ev) => this._onResizeKeydown(ev));
        handle.addEventListener('dblclick', () => this.resetHeight());

        // 窗口尺寸变化时重新约束高度，避免面板超出可视区域
        window.addEventListener('resize', () => {
            if (this.panel.classList.contains('timeline-resized')) {
                this._applyHeight(this._currentHeight(), false);
            }
            this._updateResizerAria();
        });

        // 面板高度会随内容变化，用 ResizeObserver 同步无障碍数值
        if (typeof ResizeObserver !== 'undefined') {
            this._resizeObserver = new ResizeObserver(() => this._updateResizerAria());
            this._resizeObserver.observe(this.panel);
        }

        this._updateResizerAria();
    },

    /**
     * 开始拖拽调整高度（向上变大，向下变小）
     */
    _startResize(ev) {
        if (typeof ev.button === 'number' && ev.button !== 0) return;
        ev.preventDefault();

        let startHeight;
        if (this._collapsed) {
            // 从收起状态拖动时，以指针位置为基准展开
            startHeight = Math.max(this._minHeight(), Math.round(window.innerHeight - ev.clientY));
            this._setCollapsed(false);
            this._applyHeight(startHeight, false);
        } else {
            startHeight = this.panel.getBoundingClientRect().height;
        }

        this._resizeState = {
            startY: ev.clientY,
            startHeight,
        };
        this.panel.classList.add('resizing');
        document.body.classList.add('resizing-timeline');

        this._onPointerMove = this._onPointerMove || ((event) => this._applyResizeFromPointer(event));
        this._onPointerUp = this._onPointerUp || (() => this._endResize());

        window.addEventListener('pointermove', this._onPointerMove);
        window.addEventListener('pointerup', this._onPointerUp);
        window.addEventListener('pointercancel', this._onPointerUp);

        if (this._resizer.setPointerCapture) {
            try {
                this._resizer.setPointerCapture(ev.pointerId);
            } catch (err) {
                // 忽略指针捕获失败，窗口监听仍然生效
            }
        }
    },

    _applyResizeFromPointer(ev) {
        if (!this._resizeState) return;
        const height = this._resizeState.startHeight + (this._resizeState.startY - ev.clientY);
        this._applyHeight(height, false);
    },

    /**
     * 结束拖拽并持久化高度
     */
    _endResize() {
        if (!this._resizeState) return;

        window.removeEventListener('pointermove', this._onPointerMove);
        window.removeEventListener('pointerup', this._onPointerUp);
        window.removeEventListener('pointercancel', this._onPointerUp);

        this.panel.classList.remove('resizing');
        document.body.classList.remove('resizing-timeline');
        this._resizeState = null;

        const height = this._currentHeight();
        this._writeSavedHeight(height);
        this._updateResizerAria(height);

        // 高度变化后通知拓扑图重新计算 SVG 尺寸
        window.dispatchEvent(new Event('resize'));
    },

    /**
     * 应用指定高度（带上下限约束）
     */
    _applyHeight(height, persist = true) {
        if (!this.panel) return;

        const clamped = this._clampHeight(height);
        this.panel.style.height = `${clamped}px`;
        this.panel.classList.add('timeline-resized');
        this._updateResizerAria(clamped);

        if (persist) {
            this._writeSavedHeight(clamped);
        }
    },

    /**
     * 恢复默认高度
     */
    resetHeight() {
        if (!this.panel) return;

        this.panel.style.height = '';
        this.panel.classList.remove('timeline-resized');
        this._clearSavedHeight();
        this._updateResizerAria();
        window.dispatchEvent(new Event('resize'));
    },

    /**
     * 键盘调整：↑/↓ 调整，Shift 加速，Home/End 到最小/最大
     */
    _onResizeKeydown(ev) {
        const step = ev.shiftKey ? 48 : 16;
        let nextHeight;

        switch (ev.key) {
            case 'ArrowUp':
                nextHeight = this._currentHeight() + step;
                break;
            case 'ArrowDown':
                nextHeight = this._currentHeight() - step;
                break;
            case 'Home':
                nextHeight = this._minHeightPx;
                break;
            case 'End':
                nextHeight = this._maxHeight();
                break;
            default:
                return;
        }

        ev.preventDefault();
        if (this._collapsed) this._setCollapsed(false);
        this._applyHeight(nextHeight);
        window.dispatchEvent(new Event('resize'));
    },

    /**
     * 当前可用高度范围
     */
    _minHeight() {
        return this._minHeightPx;
    },

    _maxHeight() {
        return Math.max(this._minHeightPx, window.innerHeight - 180);
    },

    _clampHeight(height) {
        const min = this._minHeight();
        const max = this._maxHeight();
        const value = Number(height);
        if (!Number.isFinite(value)) return this._defaultHeight;
        return Math.max(min, Math.min(max, Math.round(value)));
    },

    _currentHeight() {
        return this.panel ? this.panel.getBoundingClientRect().height : this._defaultHeight;
    },

    _updateResizerAria(currentHeight) {
        if (!this._resizer) return;
        const now = Math.round(
            typeof currentHeight === 'number' ? currentHeight : this._currentHeight()
        );
        this._resizer.setAttribute('aria-valuemin', String(this._minHeight()));
        this._resizer.setAttribute('aria-valuemax', String(this._maxHeight()));
        this._resizer.setAttribute('aria-valuenow', String(now));
    },

    _readSavedHeight() {
        try {
            const value = Number(window.localStorage.getItem(this._heightKey));
            return Number.isFinite(value) && value > 0 ? value : null;
        } catch (err) {
            return null;
        }
    },

    _writeSavedHeight(height) {
        try {
            window.localStorage.setItem(this._heightKey, String(Math.round(height)));
        } catch (err) {
            // 隐私模式等场景下忽略持久化失败
        }
    },

    _clearSavedHeight() {
        try {
            window.localStorage.removeItem(this._heightKey);
        } catch (err) {
            // 忽略
        }
    },

    /**
     * 增量加载事件（实时执行 / 轮询）
     * @param {Array} events - 事件数组
     */
    loadEvents(events) {
        if (!Array.isArray(events) || events.length === 0) {
            if (this.events.length === 0 && this.steps.length === 0) {
                this._showEmpty();
            }
            return;
        }

        const existing = new Set(this.events.map(e => this._eventKey(e)));
        let newCount = 0;

        for (const event of events) {
            const key = this._eventKey(event);
            if (existing.has(key)) continue;
            existing.add(key);
            this.events.push(event);
            newCount++;
        }

        if (this.events.length > this._maxEvents) {
            this.events = this.events.slice(-this._maxEvents);
        }

        if (newCount > 0) {
            this._render('bottom');
        } else {
            this._updateControls();
        }
    },

    /**
     * 用指定事件列表整体替换时间线（仅事件，无步骤）
     * @param {Array} events - 事件数组
     */
    setEvents(events) {
        this.steps = [];
        this._contextSuite = null;
        this.events = Array.isArray(events) ? events.slice() : [];
        if (this.events.length > this._maxEvents) {
            this.events = this.events.slice(-this._maxEvents);
        }
        this._render('top');
    },

    /**
     * 用一次完整执行记录刷新时间线
     * @param {Object} trace - { steps, events }
     * @param {'top'|'bottom'|'none'} scrollMode
     */
    setTrace(trace, scrollMode = 'bottom') {
        if (!trace) return;

        this.steps = Array.isArray(trace.steps) ? trace.steps.slice() : [];
        const suite = trace.suite || trace.app_name || '';
        this._contextSuite = ['banking', 'workspace', 'slack', 'travel'].includes(suite) ? suite : null;

        // 只有明确传入 events 字段时才替换事件列表；
        // 控制台执行流程会先增量加载事件，再补充步骤。
        if (Object.prototype.hasOwnProperty.call(trace, 'events')) {
            this.events = Array.isArray(trace.events) ? trace.events.slice() : [];
        }

        if (this.events.length > this._maxEvents) {
            this.events = this.events.slice(-this._maxEvents);
        }

        this._render(scrollMode);
    },

    /**
     * 只清除步骤，保留事件（用于开始一次新的实时执行）
     */
    clearTraceSteps() {
        this.steps = [];
        if (this.events.length === 0) {
            this._showEmpty();
        } else {
            this._render('none');
        }
    },

    /**
     * 清空时间线
     */
    clear() {
        this.events = [];
        this.steps = [];
        this._showEmpty();
    },

    /**
     * 事件去重键。
     * 注意不能只用 content：同一条用户指令会产生多条 content 相同的 LLM 事件，
     * 同一个工具也可能被多次调用。
     */
    _eventKey(e) {
        return [
            e.time || '',
            e.type || '',
            e.tool_intent || '',
            e.target_app || '',
            e.status || '',
            e.block_reason || '',
            e.response || '',
            e.outputs || '',
            e.content || '',
        ].join('\u0001');
    },

    /**
     * 合并步骤与事件，生成统一的展示条目。
     * 步骤提供顺序与状态，事件提供完整内容。
     */
    _buildEntries() {
        const steps = this.steps;
        const pendingEvents = this.events.slice();

        if (steps.length === 0) {
            return pendingEvents.map(event => ({
                kind: event.type === 'risk' ? 'risk' : (event.type === 'llm' ? 'llm' : 'tool'),
                step: null,
                event,
            }));
        }

        const takeNext = (predicate) => {
            for (let i = 0; i < pendingEvents.length; i++) {
                if (predicate(pendingEvents[i])) {
                    return pendingEvents.splice(i, 1)[0];
                }
            }
            return null;
        };

        const entries = [];
        for (const step of steps) {
            const name = String(step.name || '');
            let kind = 'phase';
            let event = null;

            if (name.startsWith('LLM')) {
                kind = 'llm';
                event = takeNext(e => e.type === 'llm');
            } else if (name.startsWith('工具调用')) {
                const toolName = name.replace(/^工具调用[:：]\s*/, '');
                event = takeNext(e => (e.type === 'tool' || e.type === 'risk')
                    && e.tool_intent === toolName);
                if (!event) {
                    event = takeNext(e => e.type === 'tool' || e.type === 'risk');
                }
                kind = (event && event.type === 'risk') ? 'risk' : 'tool';
            }

            entries.push({ kind, step, event });
        }

        // 未被步骤匹配到的事件（例如后端未返回步骤）追加在末尾
        for (const event of pendingEvents) {
            entries.push({
                kind: event.type === 'risk' ? 'risk' : (event.type === 'llm' ? 'llm' : 'tool'),
                step: null,
                event,
            });
        }

        return entries;
    },

    /**
     * 按当前筛选条件返回展示条目
     */
    _filteredEntries() {
        const entries = this._buildEntries();
        if (this._filter === 'all') return entries;
        return entries.filter(entry => entry.kind === this._filter);
    },

    /**
     * 显示空状态
     */
    _showEmpty() {
        if (!this.container) return;
        this.container.innerHTML = '<div class="timeline-empty">暂无执行记录，请执行操作</div>';
        this._updateFlowSummary();
        this._updateControls();
    },

    /**
     * 刷新筛选按钮和条目计数
     */
    _updateControls() {
        const entries = this._buildEntries();
        const counts = { all: entries.length, phase: 0, llm: 0, tool: 0, risk: 0 };
        for (const entry of entries) {
            if (counts[entry.kind] !== undefined) counts[entry.kind]++;
        }

        document.querySelectorAll('.timeline-filter').forEach((btn) => {
            const key = btn.dataset.filter || 'all';
            const label = btn.dataset.label || btn.textContent;
            btn.textContent = `${label} ${counts[key] || 0}`;
        });

        const countEl = document.getElementById('timelineCount');
        if (countEl) {
            const shown = this._filteredEntries().length;
            countEl.textContent = this._filter === 'all'
                ? `${shown} 条`
                : `${shown} / ${entries.length} 条`;
        }
    },

    /**
     * 渲染调用流 / 数据流完整性摘要
     */
    _updateFlowSummary() {
        const flow = document.getElementById('timelineFlow');
        if (!flow) return;

        if (this.steps.length === 0) {
            flow.hidden = true;
            flow.innerHTML = '';
            return;
        }

        const steps = this.steps;
        const blocked = steps.filter(s => s.status === 'blocked').length > 0;
        const callSteps = steps.filter(s => (s.step || 0) <= 4);
        const dataSteps = steps.filter(s => (s.step || 0) >= 5);
        const pct = (list) => {
            if (list.length === 0) return 0;
            return Math.round(list.filter(s => s.status === 'completed').length / list.length * 100);
        };
        const callPct = pct(callSteps);
        const dataPct = pct(dataSteps);
        const stateClass = (value) => blocked ? 'danger' : (value === 100 ? 'ok' : 'warn');

        flow.hidden = false;
        flow.innerHTML = `
            <span class="timeline-flow-item ${stateClass(callPct)}">调用流 <b>${callPct}%</b></span>
            <span class="timeline-flow-item ${stateClass(dataPct)}">数据流 <b>${dataPct}%</b></span>
        `;
    },

    /**
     * 渲染条目列表
     * @param {'top'|'bottom'|'none'} scrollMode - 渲染后的滚动位置
     */
    _render(scrollMode = 'none') {
        if (!this.container) return;

        this._updateFlowSummary();

        if (this.events.length === 0 && this.steps.length === 0) {
            this._showEmpty();
            return;
        }

        const visibleEntries = this._filteredEntries();
        this._updateControls();

        if (visibleEntries.length === 0) {
            this.container.innerHTML = '<div class="timeline-empty">当前筛选条件下暂无记录</div>';
            return;
        }

        const context = { lastPrompt: '' };
        let html = '';
        visibleEntries.forEach((entry, index) => {
            html += this._renderEntry(entry, index, context);
        });

        this.container.innerHTML = html;

        if (scrollMode === 'bottom') {
            this.container.scrollTop = this.container.scrollHeight;
        } else if (scrollMode === 'top') {
            this.container.scrollTop = 0;
        }
    },

    /**
     * HTML 转义，防止特殊字符破坏结构
     */
    _escape(text) {
        return String(text == null ? '' : text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    },

    /**
     * 截断长文本
     */
    _truncate(text, max) {
        text = String(text == null ? '' : text);
        return text.length > max ? text.slice(0, max) + '…' : text;
    },

    /**
     * 格式化文本：
     * - 标记 {injection_*} 未信任占位内容
     * - 思考内容支持轻量 Markdown（加粗、行内代码）
     */
    _formatText(text, mode) {
        let html = this._escape(text);

        html = html.replace(
            /\{injection_[^}]*\}/gi,
            (match) => `<mark class="timeline-untrusted" title="疑似注入占位内容">${match}</mark>`
        );

        if (mode === 'thought') {
            html = html
                .replace(/`([^`\n]+)`/g, '<code>$1</code>')
                .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
        }

        return html;
    },

    /**
     * 构建可展开的内容块
     */
    _buildContentBlock(rawText, className, previewLimit, mode) {
        const text = String(rawText == null ? '' : rawText);
        if (!text.trim()) {
            return { html: '', toggle: '', warning: '', expandable: false };
        }

        const expandable = text.length > previewLimit;
        const preview = this._formatText(this._truncate(text, previewLimit), mode);
        const full = this._formatText(text, mode);
        const warning = /\{injection_[^}]*\}/i.test(text)
            ? '<span class="timeline-warning" title="内容包含疑似注入占位符">未信任内容</span>'
            : '';
        const toggle = expandable
            ? '<button type="button" class="timeline-toggle" aria-expanded="false">展开</button>'
            : '';

        return {
            expandable,
            toggle,
            warning,
            html: `
                <div class="timeline-content ${className}">
                    <div class="timeline-preview">${preview}</div>
                    ${expandable ? `<div class="timeline-full">${full}</div>` : ''}
                </div>`,
        };
    },

    /**
     * 状态标签
     */
    _statusBadge(status) {
        switch (status) {
            case 'pending':
                return '<span class="timeline-status timeline-status-pending">等待</span>';
            case 'blocked':
                return '<span class="timeline-status timeline-status-blocked">已阻断</span>';
            case 'error':
                return '<span class="timeline-status timeline-status-error">失败</span>';
            default:
                return '<span class="timeline-status timeline-status-ok">成功</span>';
        }
    },

    /**
     * 图谱节点定位按钮
     */
    _nodeLink(nodeId) {
        if (!nodeId) return '';
        const safeId = String(nodeId).replace(/"/g, '&quot;');
        return `<button type="button" class="timeline-node-link" data-node-id="${safeId}" title="在拓扑图中定位该节点">图谱定位</button>`;
    },

    /**
     * 兼容旧 trace 的模块级 APP 名，统一为 AgentDojo 的 suite 域。
     */
    _canonicalApp(app) {
        const raw = String(app == null ? '' : app).trim();
        if (!raw || raw === 'unknown') return raw;
        const suites = ['system', 'banking', 'workspace', 'slack', 'travel'];
        if (suites.includes(raw)) return raw;

        const moduleSuites = {
            'banking_client': ['banking'],
            'file_reader': ['banking'],
            'user_account': ['banking'],
            'email': ['workspace', 'travel'],
            'email_client': ['workspace', 'travel'],
            'calendar': ['workspace', 'travel'],
            'calendar_client': ['workspace', 'travel'],
            'cloud_drive': ['workspace'],
            'cloud_drive_client': ['workspace'],
            'slack': ['slack'],
            'web': ['slack'],
            'travel': ['travel'],
            'travel_booking_client': ['travel'],
        };
        const owners = moduleSuites[raw] || [];
        if (this._contextSuite && owners.includes(this._contextSuite)) return this._contextSuite;
        if (owners.length === 1) return owners[0];
        if (owners.length > 1) return 'unified';
        return raw;
    },

    _appLabel(app) {
        const labels = {
            'system': '系统',
            'banking': '银行',
            'workspace': '办公',
            'slack': '通讯',
            'travel': '旅行',
            'unified': '统一',
        };
        return labels[app] || app || '';
    },

    /**
     * 渲染单条展示条目
     */
    _renderEntry(entry, index, context) {
        const seq = `#${String(index + 1).padStart(2, '0')}`;
        const step = entry.step || {};
        const event = entry.event || {};
        const time = this._escape(step.timestamp || event.time || '--:--:--');

        if (entry.kind === 'llm') {
            return this._renderLlmEntry(entry, seq, time, context);
        }
        if (entry.kind === 'tool' || entry.kind === 'risk') {
            return this._renderToolEntry(entry, seq, time);
        }
        return this._renderPhaseEntry(entry, seq, time);
    },

    /**
     * 生命周期阶段：用户输入 / API 请求 / 后端接收 / 图谱更新
     */
    _renderPhaseEntry(entry, seq, time) {
        const step = entry.step || {};
        const body = this._buildContentBlock(step.detail || '', 'timeline-detail', 240, 'tool');

        return `
            <article class="timeline-event timeline-event-phase${body.expandable ? ' has-detail' : ''}">
                <div class="timeline-event-header">
                    <span class="timeline-seq">${seq}</span>
                    <span class="timeline-time">${time}</span>
                    <span class="timeline-kind timeline-kind-phase">阶段</span>
                    <span class="timeline-title">${this._escape(step.name || '执行阶段')}</span>
                    ${this._statusBadge(step.status)}
                    ${this._nodeLink(step.nodeId)}
                    ${body.toggle}
                </div>
                ${body.html}
            </article>`;
    },

    /**
     * LLM 推理：Prompt（首次展示）+ 推理内容 + 决策摘要
     */
    _renderLlmEntry(entry, seq, time, context) {
        const step = entry.step || {};
        const event = entry.event || {};
        const response = String(event.response || step.detail || '');
        const prompt = String(event.prompt || '');

        let promptHtml = '';
        if (prompt && prompt !== context.lastPrompt) {
            context.lastPrompt = prompt;
            promptHtml = `
                <div class="timeline-prompt">
                    <span class="timeline-prompt-label">任务指令</span>${this._escape(this._truncate(prompt, 240))}
                </div>`;
        }

        const body = this._buildContentBlock(response, 'timeline-thought', 220, 'thought');
        const decision = (step.detail && event.response)
            ? this._buildContentBlock(step.detail, 'timeline-detail', 240, 'tool')
            : { html: '', toggle: '', warning: '', expandable: false };
        const title = step.name && step.name !== 'LLM 推理' ? step.name : '思考与决策';

        return `
            <article class="timeline-event timeline-event-llm${(body.expandable || decision.expandable) ? ' has-detail' : ''}">
                <div class="timeline-event-header">
                    <span class="timeline-seq">${seq}</span>
                    <span class="timeline-time">${time}</span>
                    <span class="timeline-kind timeline-kind-llm">LLM</span>
                    <span class="timeline-title">${this._escape(title)}</span>
                    ${body.warning}
                    ${this._statusBadge(step.status)}
                    ${this._nodeLink(step.nodeId)}
                    ${body.toggle || decision.toggle}
                </div>
                ${promptHtml}
                ${decision.html}
                ${body.html}
            </article>`;
    },

    /**
     * 工具调用 / 风险事件：工具名 + 目标 APP + 输出 / 阻断原因
     */
    _renderToolEntry(entry, seq, time) {
        const step = entry.step || {};
        const event = entry.event || {};
        const isRisk = entry.kind === 'risk';
        const toolName = event.tool_intent
            || String(step.name || '').replace(/^工具调用[:：]\s*/, '')
            || '未知工具';
        const appDomain = event.target_app ? this._canonicalApp(event.target_app) : '';
        const app = appDomain
            ? `<span class="timeline-chip">${this._escape(this._appLabel(appDomain))}</span>`
            : '';

        const blockReason = event.block_reason
            ? `<div class="timeline-content timeline-block">${this._formatText(event.block_reason, 'tool')}</div>`
            : '';

        const outputText = event.outputs || (!event.tool_intent ? step.detail : '');
        const body = this._buildContentBlock(outputText, 'timeline-result', 180, 'tool');

        return `
            <article class="timeline-event ${isRisk ? 'timeline-event-risk' : 'timeline-event-tool'}${body.expandable ? ' has-detail' : ''}">
                <div class="timeline-event-header">
                    <span class="timeline-seq">${seq}</span>
                    <span class="timeline-time">${time}</span>
                    <span class="timeline-kind ${isRisk ? 'timeline-kind-risk' : 'timeline-kind-tool'}">${isRisk ? '风险' : '工具'}</span>
                    <span class="timeline-title timeline-tool-name">${this._escape(toolName)}</span>
                    ${app}
                    ${body.warning}
                    ${this._statusBadge(step.status || (isRisk ? 'blocked' : (event.status === 'error' ? 'error' : 'completed')))}
                    ${this._nodeLink(step.nodeId)}
                    ${body.toggle}
                </div>
                ${blockReason}
                ${body.html}
            </article>`;
    }
};
