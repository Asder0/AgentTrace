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
    _selectedRiskId: null,

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
        this._bindInteractions();
    },

    _bindInteractions() {
        if (!this.container || this._interactionsBound) return;
        this._interactionsBound = true;
        const activate = (target) => {
            const cardEl = target.closest('.risk-card[data-risk-index]');
            if (!cardEl) return;
            const index = Number(cardEl.dataset.riskIndex);
            const card = this.riskCards[index];
            if (!card) return;
            this.focusGraph(card, cardEl);
        };
        this.container.addEventListener('click', (event) => {
            const cardEl = event.target.closest('.risk-card[data-risk-index]');
            if (!cardEl) return;
            if (event.target.closest('details, a, input')) return;
            if (
                event.target.closest('button')
                && !event.target.closest('[data-risk-focus]')
            ) {
                return;
            }
            activate(event.target);
        });
        this.container.addEventListener('keydown', (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            const cardEl = event.target.closest('.risk-card[data-risk-index]');
            if (!cardEl || event.target.closest('button, summary, a')) {
                return;
            }
            event.preventDefault();
            activate(cardEl);
        });
    },

    async focusGraph(card, cardEl) {
        if (typeof GRAPH === 'undefined') return false;
        let focused = false;
        const applyFocus = () => {
            focused = typeof GRAPH.focusRiskContext === 'function'
                ? GRAPH.focusRiskContext(card)
                : false;
            if (!focused && GRAPH.flashNode) {
                const nodeId = card.graph_focus?.risk_node_id
                    || card.graph_focus?.activity_node_id
                    || card.risk_id;
                focused = GRAPH.flashNode(nodeId) !== false;
            }
        };
        if ((!GRAPH.nodes || GRAPH.nodes.length === 0) && GRAPH.loadData) {
            try {
                await GRAPH.loadData();
            } catch (_err) {
                return false;
            }
        }
        applyFocus();
        if (focused) {
            this._selectedRiskId = this._cardId(card);
            this.container
                .querySelectorAll('.risk-card.is-selected')
                .forEach(item => item.classList.remove('is-selected'));
            cardEl?.classList.add('is-selected');
            const timelineNodeId = card.graph_focus?.activity_node_id
                || card.graph_focus?.risk_node_id
                || card.risk_id;
            if (
                typeof TIMELINE !== 'undefined'
                && TIMELINE.focusNode
            ) {
                TIMELINE.focusNode(timelineNodeId);
            }
        }
        return focused;
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
            const cards = this.dedupeCards([
                ...riskCards,
                ...policyCards,
            ]);
            this.render(cards);
            return this.riskCards;
        } catch (err) {
            console.error('加载风险与策略事件失败:', err);
        }
        return this.riskCards;
    },

    dedupeCards(cards) {
        if (!Array.isArray(cards)) return [];
        const labels = window.AgentTraceRiskLabels;
        const seen = new Set();
        const result = [];
        for (const rawCard of cards) {
            const card = labels?.normalizeCard
                ? labels.normalizeCard(rawCard)
                : rawCard;
            if (!card) continue;
            const eventId = String(
                card.risk_id || card.event_id || ''
            );
            const normalizedCard = eventId && !card.risk_id
                ? { ...card, risk_id: eventId }
                : card;
            const identity = [
                eventId,
                normalizedCard.ring,
                normalizedCard.policy_id || '',
                normalizedCard.phase || '',
                normalizedCard.action
                    || normalizedCard.tool_intent
                    || '',
            ].join('|');
            const keys = [`semantic:${identity}`];
            if (eventId) keys.push(`event:${eventId}`);
            if (keys.some(key => seen.has(key))) continue;
            keys.forEach(key => seen.add(key));
            result.push(normalizedCard);
        }
        return result;
    },

    _policyToCard(event) {
        const decision = String(event.decision || 'ADVISORY').toUpperCase();
        return {
            ...event,
            risk_id: event.risk_id || event.event_id,
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
            this._selectedRiskId = null;
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
        for (const [cardIndex, card] of normalizedCards.entries()) {
            const ring = card.ring || 0;
            const ringClass = `ring${ring}`;
            const meta = ringMeta[ring] || { color: '#8899aa', action: '未知' };
            const userView = card.user_view || {};
            const riskType = this._escape(
                userView.risk_type
                || card.risk_type
                || labels?.titleFor?.(ring, card.policy_id)
                || '安全风险'
            );
            const userContent = this._escape(
                userView.content
                || card.user_content
                || card.defense_detail
                || card.detail
                || '系统检测到一项与当前任务相关的风险。'
            );
            const userReason = this._escape(
                userView.reason
                || card.user_reason
                || card.defense_detail
                || card.detail
                || '该操作需要根据当前任务授权和安全策略进行处理。'
            );
            const defenseAction = this._escape(
                card.defense_action || meta.action
            );
            const technicalTitle = this._escape(
                card.defense_ring || card.title || '安全事件'
            );
            const defenseDetail = this._escape(
                card.defense_detail || card.detail || '无详细信息'
            );
            const defenseEffect = this._escape(
                card.defense_effect || '未知防御效果'
            );
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
            const levelLabel = (
                userView.risk_type === '敏感数据授权'
                || card.risk_type === '敏感数据授权'
            ) ? '敏感等级' : '风险等级';
            const levelValue = (
                userView.risk_type === '敏感数据授权'
                || card.risk_type === '敏感数据授权'
            )
                ? (userView.sensitivity_level
                    || card.sensitivity_level
                    || severity)
                : severity;
            const phaseLabel = (
                card.policy_id
                === 'ring2.sensitive_data_exposure_confirmation'
            )
                ? (
                    card.phase === 'post_execution_runtime_detection'
                    || card.fsm_before === 'OUTPUT_OBSERVED'
                        ? '运行后二次确认'
                        : '读取前授权'
                )
                : '';
            const policy = this._escape(card.policy_id || '');
            const evidence = [
                ...(card.evidence_entity_ids || []),
                ...(card.source_ids || []),
                ...(card.sink_ids || []),
            ].slice(0, 6).map(value => this._escape(value)).join(' · ');
            const injectionEvidence = Array.isArray(
                userView.injection_evidence
                || card.injection_evidence
            )
                ? (userView.injection_evidence
                    || card.injection_evidence)
                : [];
            const injectionEvidenceHtml = injectionEvidence.length
                ? `
                    <div class="risk-injection-evidence">
                        <div class="risk-injection-title">检测到的注入内容</div>
                        ${injectionEvidence.map(item => `
                            <div class="risk-injection-item">
                                <span class="risk-injection-field">${this._escape(
                                    item.field || 'unknown'
                                )}</span>
                                <pre class="risk-injection-text">${this._escape(
                                    item.content || ''
                                )}</pre>
                            </div>
                        `).join('')}
                    </div>
                `
                : '';
            
            const kindClass = card.event_kind === 'policy' ? ' policy-card' : ' security-card';
            const cardId = this._escape(this._cardId(card));
            html += `
                <div class="risk-card${kindClass}"
                     data-risk-index="${cardIndex}"
                     data-risk-id="${cardId}"
                     role="button"
                     tabindex="0"
                     aria-label="查看该风险对应的数据链">
                    <div class="risk-title">
                        <span class="risk-ring ${ringClass}">${riskType}</span>
                        <span class="risk-kind-badge">${decisionLabel}</span>
                        ${phaseLabel ? `<span class="risk-kind-badge risk-phase-badge">${phaseLabel}</span>` : ''}
                        <span class="risk-kind-badge">${levelLabel}：${this._escape(levelValue)}</span>
                    </div>
                    <div class="risk-detail">
                        ${injectionEvidenceHtml}
                        <div class="defense-section">
                            <div class="defense-row">
                                <span class="defense-label">具体内容</span>
                                <span class="defense-value defense-detail-text">${userContent}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">风险分析</span>
                                <span class="defense-value defense-detail-text">${userReason}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">系统处理</span>
                                <span class="defense-value defense-action-${this._escape(String(card.decision || '').toLowerCase())}">${defenseAction}</span>
                            </div>
                        </div>
                        <button type="button"
                                class="risk-focus-btn"
                                data-risk-focus
                                title="在溯源图谱中高亮相关数据链">
                            查看数据链
                        </button>
                        <details class="risk-technical-details">
                            <summary>查看审计信息</summary>
                            <div class="defense-meta">
                                检测环节：${technicalTitle} |
                                智能体：${this._escape(card.agent || '未知')} |
                                动作：${this._escape(card.action || '未知')} |
                                APP：${this._escape(
                                    window.AgentTraceAppCatalog?.appLabel
                                        ? window.AgentTraceAppCatalog.appLabel(card.app)
                                        : card.app || '未知'
                                )}
                            </div>
                            ${policy ? `<div class="defense-meta">策略：${policy}</div>` : ''}
                            <div class="defense-meta">最终状态：${decisionLabel}</div>
                            <details class="risk-technical-details">
                                <summary>检测时技术记录</summary>
                                <div class="defense-meta">检测时状态：${defenseEffect}</div>
                                <div class="defense-meta">检测时原因：${defenseDetail}</div>
                                ${evidence ? `<div class="defense-meta">证据数量：${evidence ? evidence.split(' · ').length : 0} 项</div>` : ''}
                            </details>
                        </details>
                    </div>
                </div>
            `;
        }

        this.container.innerHTML = html;
        if (this._selectedRiskId) {
            const selected = [...this.container.querySelectorAll(
                '.risk-card[data-risk-id]'
            )].find(item =>
                item.dataset.riskId === this._selectedRiskId
            );
            if (selected) {
                selected.classList.add('is-selected');
            } else {
                this._selectedRiskId = null;
            }
        }
    },

    _cardId(card) {
        return String(card?.risk_id || card?.event_id || '');
    },

    clearSelection() {
        this._selectedRiskId = null;
        if (!this.container) return;
        this.container
            .querySelectorAll('.risk-card.is-selected')
            .forEach(item => item.classList.remove('is-selected'));
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
        this.clearSelection();
        this._showEmpty();
    }
};
