/**
 * 事件时间线模块 - 展示 Agent 操作的详细事件历史
 *
 * 功能：
 * - 统一展示 LLM 思考（含推理内容）与工具调用（含调用结果）
 * - 风险事件（被阻断的工具调用）以红色高亮显示
 * - 自动滚动到最新事件
 */

const TIMELINE = {
    container: null,
    events: [],

    /**
     * 初始化时间线
     */
    init() {
        this.container = document.getElementById('timelineEvents');
        if (!this.container) {
            console.warn('时间线容器不存在');
            return;
        }
        this._showEmpty();
    },

    /**
     * 加载事件数据
     * @param {Array} events - 事件数组
     */
    loadEvents(events) {
        if (!Array.isArray(events) || events.length === 0) {
            if (this.events.length === 0) {
                this._showEmpty();
            }
            return;
        }

        // 合并新事件（去重）
        const existingContents = new Set(this.events.map(e => e.content));
        let newCount = 0;

        for (const event of events) {
            if (!existingContents.has(event.content)) {
                this.events.push(event);
                existingContents.add(event.content);
                newCount++;
            }
        }

        if (newCount > 0) {
            this._render();
        }
    },

    /**
     * 用指定事件列表整体替换时间线（用于历史记录回放）
     * @param {Array} events - 事件数组
     */
    setEvents(events) {
        this.events = Array.isArray(events) ? events.slice() : [];
        this._render();
    },

    /**
     * 清空时间线
     */
    clear() {
        this.events = [];
        this._showEmpty();
    },

    /**
     * 显示空状态
     */
    _showEmpty() {
        if (!this.container) return;
        this.container.innerHTML = '<div class="timeline-empty">暂无事件记录，请执行操作</div>';
    },

    /**
     * 渲染事件列表
     */
    _render() {
        if (!this.container) return;

        if (this.events.length === 0) {
            this._showEmpty();
            return;
        }

        let html = '';
        for (const event of this.events) {
            html += this._renderEvent(event);
        }

        this.container.innerHTML = html;

        // 自动滚动到底部（最新事件）
        this.container.scrollTop = this.container.scrollHeight;
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
     * 渲染单条事件
     * LLM 事件：展示智能体思考内容（推理）与输入指令
     * 工具/风险事件：展示工具名、调用结果、阻断原因
     */
    _renderEvent(e) {
        const time = this._escape(e.time || '--:--:--');

        if (e.type === 'llm') {
            const response = this._escape(this._truncate(e.response, 500));
            const prompt = this._escape(this._truncate(e.prompt, 200));
            return `
                <div class="timeline-event timeline-event-llm">
                    <div class="timeline-event-header">
                        <span class="timeline-time">${time}</span>
                        <span class="timeline-icon">🧠</span>
                        <span class="timeline-title">LLM 思考</span>
                    </div>
                    ${response ? `<div class="timeline-thought">💭 ${response}</div>` : ''}
                    ${prompt ? `<div class="timeline-prompt">💬 指令: ${prompt}</div>` : ''}
                </div>`;
        }

        // 工具调用（含被阻断的风险事件）
        const isRisk = e.type === 'risk';
        const icon = isRisk ? '🚨' : '🔧';
        const tool = this._escape(e.tool_intent || '未知工具');
        const app = e.target_app ? this._escape(e.target_app) : '';
        const outputs = this._escape(this._truncate(e.outputs, 400));
        const blockReason = this._escape(e.block_reason || '');

        let statusBadge = '<span class="timeline-status timeline-status-ok">成功</span>';
        if (isRisk) {
            statusBadge = '<span class="timeline-status timeline-status-blocked">已阻断</span>';
        } else if (e.status === 'error') {
            statusBadge = '<span class="timeline-status timeline-status-error">失败</span>';
        }

        return `
            <div class="timeline-event ${isRisk ? 'timeline-event-risk' : 'timeline-event-tool'}">
                <div class="timeline-event-header">
                    <span class="timeline-time">${time}</span>
                    <span class="timeline-icon">${icon}</span>
                    <span class="timeline-title">工具调用: ${tool}${app ? `（${app}）` : ''}</span>
                    ${statusBadge}
                </div>
                ${blockReason ? `<div class="timeline-block">🚫 ${blockReason}</div>` : ''}
                ${outputs ? `<div class="timeline-result">📤 结果: ${outputs}</div>` : ''}
            </div>`;
    }
};
