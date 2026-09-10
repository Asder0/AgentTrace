/**
 * 指令流转追踪面板 - 展示指令从输入到执行的完整流转过程
 * 
 * 基于后端返回的真实执行事件构建追踪步骤。
 * 展示 LLM 真实的调用流和数据流，不进行任何硬编码解析。
 * 
 * 提供：
 * - 指令流转步骤可视化
 * - 数据流完整性指示器
 * 属于图谱五类节点（AIAgent/AIModelInvocation/Prompt/AgentTool/DomainData）的步骤
 * 均可点击，在拓扑图中定位并查看该节点详情。
 */
const TRACE_PANEL = {
    /** 当前追踪 ID */
    _currentTraceId: null,
    
    /** 当前追踪数据 */
    _currentTrace: null,

    /**
     * 初始化追踪面板
     */
    init() {
        this._createPanel();
        this._bindEvents();
    },

    /**
     * 创建追踪面板 DOM
     */
    _createPanel() {
        const sidePanel = document.querySelector('.side-panel');
        if (!sidePanel) return;

        const panel = document.createElement('div');
        panel.className = 'card trace-panel';
        panel.id = 'tracePanel';
        panel.innerHTML = `
            <div class="trace-panel-header">
                <h3>指令流转追踪</h3>
                <span class="trace-panel-subtitle">追踪指令的完整生命周期，点击步骤定位节点</span>
            </div>
            
            <!-- 追踪步骤 -->
            <div class="trace-steps" id="traceSteps">
                <div class="trace-step trace-step-empty">
                    <span class="trace-step-text">执行指令后将在此显示完整的流转追踪</span>
                </div>
            </div>

            <!-- 数据流完整性 -->
            <div class="trace-section" id="traceDataflowSection" style="display:none;">
                <div class="trace-section-title">数据流完整性</div>
                <div class="trace-dataflow" id="traceDataflow">
                    <div class="trace-dataflow-item">
                        <span class="trace-dataflow-label">调用流</span>
                        <div class="trace-dataflow-bar" id="traceCallFlowBar">
                            <div class="trace-dataflow-fill" id="traceCallFlowFill" style="width:0%"></div>
                        </div>
                        <span class="trace-dataflow-pct" id="traceCallFlowPct">0%</span>
                    </div>
                    <div class="trace-dataflow-item">
                        <span class="trace-dataflow-label">数据流</span>
                        <div class="trace-dataflow-bar" id="traceDataFlowBar">
                            <div class="trace-dataflow-fill" id="traceDataFlowFill" style="width:0%"></div>
                        </div>
                        <span class="trace-dataflow-pct" id="traceDataFlowPct">0%</span>
                    </div>
                </div>
            </div>
        `;

        // 插入到控制台之后
        const consoleCard = document.querySelector('.console-card');
        const statsCard = document.querySelector('.stats-card');
        if (consoleCard && statsCard) {
            sidePanel.insertBefore(panel, statsCard);
        } else {
            sidePanel.appendChild(panel);
        }
    },

    /**
     * 绑定事件
     * 注意：追踪面板不再主动调用独立的追踪 API，
     * 而是由 console.js 在执行完成后将结果直接传入 _renderTrace。
     * 这里只保留事件监听用于清空等操作。
     */
    _bindEvents() {
        // 不再需要监听 custom_command 和 scenario_executed 来调用追踪 API
        // 追踪信息已包含在执行结果中，由 console.js 直接传入 _renderTrace
    },

    /**
     * 渲染追踪结果
     * 基于后端返回的真实执行事件构建追踪步骤
     */
    _renderTrace(trace) {
        // 渲染步骤
        this._renderSteps(trace.steps);

        // 渲染数据流完整性
        this._renderDataflow(trace.steps);
    },

    /**
     * 渲染追踪步骤
     * 属于五类图谱节点的步骤会添加 data-node-id 属性，点击可定位并查看节点详情
     */
    _renderSteps(steps) {
        const container = document.getElementById('traceSteps');
        if (!container) return;

        let html = '';
        for (const step of steps) {
            const stepName = this._escape(step.name || '未知步骤');
            const stepDetail = this._escape(step.detail || '');
            const stepTime = this._escape(step.timestamp || '');
            const statusClass = step.status === 'completed' ? 'trace-step-completed' 
                : step.status === 'pending' ? 'trace-step-pending'
                : step.status === 'blocked' ? 'trace-step-blocked'
                : 'trace-step-error';
            
            const statusText = step.status === 'completed' ? '完成'
                : step.status === 'pending' ? '等待'
                : step.status === 'blocked' ? '已阻断'
                : '失败';

            // 工具调用步骤添加 data-node-id 属性，用于点击定位图谱节点
            const safeNodeId = String(step.nodeId || '').replace(/"/g, '&quot;');
            const nodeIdAttr = safeNodeId ? ` data-node-id="${safeNodeId}"` : '';
            // 工具调用步骤添加可点击样式
            const clickableClass = step.nodeId ? ' trace-step-clickable' : '';

            html += `
                <div class="trace-step ${statusClass}${clickableClass}"${nodeIdAttr}>
                    <div class="trace-step-header">
                        <span class="trace-step-name">${stepName}</span>
                        <span class="trace-step-status">${statusText}</span>
                    </div>
                    <div class="trace-step-detail">${stepDetail}</div>
                    <div class="trace-step-time">${stepTime}</div>
                </div>
            `;
        }

        container.innerHTML = html;

        // 为有 nodeId 的步骤绑定点击事件：定位节点并查看节点详情
        container.querySelectorAll('.trace-step-clickable').forEach(el => {
            el.addEventListener('click', function() {
                const nodeId = this.getAttribute('data-node-id');
                if (!nodeId || typeof GRAPH === 'undefined') return;
                if (GRAPH.flashNode) GRAPH.flashNode(nodeId);
                const node = (GRAPH.nodes || []).find(n => n.id === nodeId);
                if (node && GRAPH.showNodeDetail) GRAPH.showNodeDetail(node);
            });
        });
    },

    /**
     * HTML 转义，防止后端文本破坏结构
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
     * 渲染数据流完整性
     * 支持阻断状态：当有步骤被阻断时，显示红色阻断标记
     */
    _renderDataflow(steps) {
        const section = document.getElementById('traceDataflowSection');
        if (!section) return;

        // 计算完成度
        const totalSteps = steps.length;
        const completedSteps = steps.filter(s => s.status === 'completed').length;
        const blockedSteps = steps.filter(s => s.status === 'blocked').length;
        const isBlocked = blockedSteps > 0;

        // 调用流：步骤 1-4 的完成度（用户输入 → API请求 → 后端接收 → LLM推理）
        const callFlowSteps = steps.filter(s => s.step <= 4);
        const callFlowCompleted = callFlowSteps.filter(s => s.status === 'completed').length;
        const callFlowPct = callFlowSteps.length > 0 
            ? Math.round((callFlowCompleted / callFlowSteps.length) * 100) 
            : 0;

        // 数据流：步骤 5+（工具调用 → 图谱更新）的完成度
        const dataFlowSteps = steps.filter(s => s.step >= 5);
        const dataFlowCompleted = dataFlowSteps.filter(s => s.status === 'completed').length;
        const dataFlowPct = dataFlowSteps.length > 0 
            ? Math.round((dataFlowCompleted / dataFlowSteps.length) * 100) 
            : 0;

        section.style.display = 'block';

        // 如果被阻断，在数据流完整性区域显示阻断标记
        const existingBlockedLabel = section.querySelector('.trace-blocked-label');
        if (isBlocked) {
            if (!existingBlockedLabel) {
                const label = document.createElement('div');
                label.className = 'trace-blocked-label';
                label.textContent = '执行已被防御系统阻断';
                section.insertBefore(label, section.querySelector('.trace-dataflow'));
            }
        } else {
            if (existingBlockedLabel) {
                existingBlockedLabel.remove();
            }
        }

        const callFlowFill = document.getElementById('traceCallFlowFill');
        const callFlowPctEl = document.getElementById('traceCallFlowPct');
        if (callFlowFill) {
            callFlowFill.style.width = callFlowPct + '%';
            callFlowFill.className = 'trace-dataflow-fill '
                + (isBlocked ? 'fill-danger' : (callFlowPct === 100 ? 'fill-ok' : 'fill-warn'));
        }
        if (callFlowPctEl) callFlowPctEl.textContent = callFlowPct + '%';

        const dataFlowFill = document.getElementById('traceDataFlowFill');
        const dataFlowPctEl = document.getElementById('traceDataFlowPct');
        if (dataFlowFill) {
            dataFlowFill.style.width = dataFlowPct + '%';
            dataFlowFill.className = 'trace-dataflow-fill '
                + (isBlocked ? 'fill-danger' : (dataFlowPct === 100 ? 'fill-ok' : 'fill-warn'));
        }
        if (dataFlowPctEl) dataFlowPctEl.textContent = dataFlowPct + '%';
    },

    /**
     * 显示错误
     */
    _showError(message) {
        const container = document.getElementById('traceSteps');
        if (!container) return;

        container.innerHTML = `
            <div class="trace-step trace-step-error">
                <div class="trace-step-header">
                    <span class="trace-step-name">追踪失败</span>
                </div>
                <div class="trace-step-detail">${message}</div>
            </div>
        `;
    },

    /**
     * 清空追踪
     */
    clear() {
        this._currentTraceId = null;
        this._currentTrace = null;

        const container = document.getElementById('traceSteps');
        if (container) {
            container.innerHTML = `
                <div class="trace-step trace-step-empty">
                    <span class="trace-step-text">执行指令后将在此显示完整的流转追踪</span>
                </div>
            `;
        }

        // 隐藏各区域
        const sections = ['traceParseSection', 'traceCompareSection', 'traceDataflowSection'];
        for (const id of sections) {
            const el = document.getElementById(id);
            if (el) el.style.display = 'none';
        }
    }
};
