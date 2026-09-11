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
            const cards = await API.getRiskCards();
            if (Array.isArray(cards)) {
                this.render(cards);
                return cards;
            }
        } catch (err) {
            console.error('加载风险卡片失败:', err);
        }
        return this.riskCards;
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

        this.riskCards = cards;

        // Ring 对应的颜色与默认动作
        const ringMeta = {
            1: { color: '#f85149', action: '阻断' },
            2: { color: '#d29922', action: '阻断' },
            3: { color: '#a371f7', action: '脱敏' },
            0: { color: '#4f8cff', action: '阻断' },
        };

        let html = '';
        for (const card of cards) {
            const ring = card.ring || 0;
            const ringClass = `ring${ring}`;
            const meta = ringMeta[ring] || { color: '#8899aa', action: '未知' };
            
            // 使用后端返回的防御诊断详情，如果没有则使用默认值
            const defenseRing = this._escape(card.defense_ring || card.title || '安全事件');
            const defenseAction = this._escape(card.defense_action || meta.action);
            const defenseDetail = this._escape(card.defense_detail || card.detail || '无详细信息');
            const defenseEffect = this._escape(card.defense_effect || '未知防御效果');
            
            html += `
                <div class="risk-card">
                    <div class="risk-title">
                        <span class="risk-ring ${ringClass}">Ring ${ring}</span>
                        ${defenseRing}
                    </div>
                    <div class="risk-detail">
                        <div class="defense-section">
                            <div class="defense-row">
                                <span class="defense-label">触发环节</span>
                                <span class="defense-value">${defenseRing}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">防御动作</span>
                                <span class="defense-value defense-action-${defenseAction}">${defenseAction}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">检测详情</span>
                                <span class="defense-value defense-detail-text">${defenseDetail}</span>
                            </div>
                            <div class="defense-row">
                                <span class="defense-label">防御效果</span>
                                <span class="defense-value defense-effect-text">${defenseEffect}</span>
                            </div>
                        </div>
                        <div class="defense-meta">
                            Agent: ${this._escape(card.agent || 'unknown')} |
                            Action: ${this._escape(card.action || 'unknown')} |
                            APP: ${this._escape(card.app || 'unknown')}
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
        this.container.innerHTML = '<div class="risk-empty">暂无风险事件</div>';
    },

    /**
     * 清空风险卡片
     */
    clear() {
        this.riskCards = [];
        this._showEmpty();
    }
};
