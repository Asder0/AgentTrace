/**
 * 风险卡片面板模块 - 展示安全风险事件
 * 
 * 功能：
 * - 显示风险卡片列表（按 Ring 分类）
 * - 风险卡片包含 Ring 编号、标题、详情
 * - 自动更新风险卡片
 * - 风险计数
 * - 空状态提示
 */

const RISK_PANEL = {
    container: null,
    riskCards: [],

    /**
     * 初始化风险卡片面板
     */
    init() {
        this.container = document.getElementById('riskCards');
        if (!this.container) {
            console.warn('风险卡片容器不存在');
            return;
        }

        // 显示空状态
        this._showEmpty();
    },

    /**
     * 加载风险卡片数据
     */
    async loadRiskCards() {
        try {
            const [riskResult, policyResult] = await Promise.allSettled([
                API.getRiskCards(),
                API.getPolicyEvents(),
            ]);
            const riskCards = riskResult.status === 'fulfilled'
                && Array.isArray(riskResult.value)
                ? riskResult.value
                : [];
            const policyCards = policyResult.status === 'fulfilled'
                && Array.isArray(policyResult.value)
                ? policyResult.value.map(event => this._policyToCard(event))
                : [];
            const cards = [...riskCards, ...policyCards];
            this.render(cards);
            return this.riskCards;
        } catch (err) {
            console.error('加载风险与策略事件失败:', err);
        }
        return this.riskCards;
    },

    _policyToCard(event) {
        const decision = String(event.decision || 'ADVISORY').toUpperCase();
        return {
            ...event,
            event_kind: 'policy',
            title: event.title || `Ring ${event.ring || '?'}: 策略事件`,
            action: event.action
                || event.tool_intent
                || (Array.isArray(event.sink_ids) ? event.sink_ids[0] : '')
                || 'unknown',
            app: event.app || event.target_app || 'system',
            defense_detail: event.detail || event.reason || '策略事件',
            severity: event.severity || (decision === 'BLOCK' ? 'high' : 'medium'),
        };
    },

    /**
     * 渲染风险卡片
     * @param {Array} cards - 风险卡片数组
     */
    render(cards) {
        if (!this.container) return;

        if (!Array.isArray(cards) || cards.length === 0) {
            this._showEmpty();
            this.riskCards = [];
            return;
        }

        const labels = window.AgentTraceRiskLabels;
        const normalizedCards = labels
            ? cards.map(card => labels.normalizeCard(card))
            : cards;
        this.riskCards = normalizedCards;

        // Ring 对应的颜色与默认动作
        const ringMeta = {
            1: { color: '#d29922', action: '告警' },
            2: { color: '#f85149', action: '阻断' },
            3: { color: '#a371f7', action: '阻断' },
            0: { color: '#4f8cff', action: '阻断' },
        };

        let html = '';
        for (const card of normalizedCards) {
            const ring = card.ring || 0;
            const ringClass = `ring${ring}`;
            const meta = ringMeta[ring] || { color: '#8899aa', action: '未知' };
            // 使用后端返回的防御诊断详情，如果没有则使用默认值
            const defenseRing = this._escape(
                card.defense_ring || card.title || '安全事件'
            );
            const defenseAction = this._escape(
                card.defense_action || meta.action
            );
            const defenseDetail = this._escape(card.defense_detail || card.detail || '无详细信息');
            const defenseEffect = this._escape(card.defense_effect || '未知防御效果');
            const severity = this._escape(
                card.severity_label
                || labels?.severityLabels?.[card.severity]
                || card.severity
                || '中'
            );
            const decisionLabel = this._escape(
                card.decision_label
                || labels?.decisionLabels?.[card.decision]
                || card.decision
                || '告警'
            );
            const policy = this._escape(card.policy_id || '');
            const evidence = [
                ...(card.evidence_entity_ids || []),
                ...(card.source_ids || []),
                ...(card.sink_ids || []),
            ].slice(0, 6).map(value => this._escape(value)).join(' · ');
            
            const kindClass = card.event_kind === 'policy' ? ' policy-card' : ' security-card';
            html += `
                <div class="risk-card${kindClass}">
                    <div class="risk-title">
                        <span class="risk-ring ${ringClass}">Ring ${ring}</span>
                        ${defenseRing}
                        <span class="risk-kind-badge">${card.event_kind === 'policy' ? '策略' : '安全'}</span>
                    </div>
                    <div class="risk-detail">
                        <div class="defense-section">
                            <div class="defense-row">
                                <span class="defense-label">触发环节</span>
                                <span class="defense-value">${defenseRing}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">防御动作</span>
                                <span class="defense-value defense-action-${this._escape(String(card.decision || '').toLowerCase())}">${defenseAction}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">检测详情</span>
                                <span class="defense-value defense-detail-text">${defenseDetail}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">防御效果</span>
                                <span class="defense-value defense-effect-text">${defenseEffect}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">决策 / 等级</span>
                                <span class="defense-value">${decisionLabel} / ${severity}</span>
                            </div>
                            ${policy ? `<div class="defense-row">
                                <span class="defense-label">策略</span>
                                <span class="defense-value">${policy}</span>
                            </div>` : ''}
                            ${evidence ? `<div class="defense-row">
                                <span class="defense-label">证据路径</span>
                                <span class="defense-value">${evidence}</span>
                            </div>` : ''}
                        </div>
                        <div class="defense-meta">
                            智能体：${this._escape(card.agent || '未知')} |
                            动作：${this._escape(card.action || '未知')} |
                            APP：${this._escape(
                                window.AgentTraceAppCatalog?.appLabel
                                    ? window.AgentTraceAppCatalog.appLabel(card.app)
                                    : card.app || '未知'
                            )}
                        </div>
                    </div>
                </div>
            `;
        }

        this.container.innerHTML = html;
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
     * 显示空状态
     */
    _showEmpty() {
        if (!this.container) return;
        this.container.innerHTML = '<div class="risk-empty">暂无风险或策略事件</div>';
    },

    /**
     * 清空风险卡片
     */
    clear() {
        this.riskCards = [];
        this._showEmpty();
    }
};
