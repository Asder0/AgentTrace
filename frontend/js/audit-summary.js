/**
 * Task-level audit summary derived from the rendered PROV graph.
 * It presents authorization scope, cross-APP route, sensitivity and policy
 * outcome without duplicating the complete graph or timeline.
 */
const AUDIT_SUMMARY = {
    render(graph) {
        const body = document.getElementById('auditSummaryBody');
        const statusEl = document.getElementById('auditSummaryStatus');
        if (!body || !statusEl || !graph) return;

        const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
        const labels = window.AgentTraceRiskLabels || {};
        const tools = nodes.filter(node => node.type === 'AgentTool');
        const dataNodes = nodes.filter(node => node.type === 'DomainData');
        const decisions = nodes.filter(node =>
            node.type === 'RiskEvent' || node.type === 'PolicyEvent'
        );
        const plan = this._latestPlan(tools);
        const route = this._crossAppRoute(tools, graph);
        const sensitive = dataNodes.filter(node => this._isSensitive(node));
        const untrusted = dataNodes.filter(node => this._isUntrusted(node));
        const injectionFlagged = [...dataNodes, ...tools].filter(node =>
            this._isInjectionRisky(node)
        );
        const categories = this._categories([...dataNodes, ...tools]);
        const egressNodes = nodes.filter(node =>
            node.type === 'EgressSink'
            || (node.type === 'AgentTool' && node.egress)
        );
        const blocked = decisions.find(node =>
            String(node.decision || '').toUpperCase() === 'BLOCK'
        );
        const advisory = decisions.find(node =>
            String(node.decision || '').toUpperCase() === 'ADVISORY'
        );
        const mitigated = decisions.find(node =>
            String(node.decision || '').toUpperCase() === 'MITIGATE'
        );
        const taskState = [...nodes].reverse().find(node =>
            node.type === 'TaskState'
            && node.scope === 'task'
            && node.terminal === true
        );
        const taskOutcome = String(taskState?.state || '').toUpperCase();
        const taskIncomplete = [
            'INCOMPLETE',
            'FAILED',
            'CANCELLED',
        ].includes(taskOutcome);

        let statusClass = 'ok';
        let statusText = tools.length ? '检查通过' : '等待任务';
        if (blocked || taskOutcome === 'BLOCKED') {
            statusClass = 'blocked';
            statusText = '已阻断';
        } else if (taskIncomplete) {
            statusClass = 'warning';
            statusText = '任务未完成';
        } else if (advisory || mitigated) {
            statusClass = 'warning';
            statusText = mitigated ? '已隔离风险' : '存在提醒';
        }

        statusEl.className = `audit-summary-status ${statusClass}`;
        statusEl.textContent = statusText;

        const allowedActions = this._unique(plan.allowed_actions || []);
        const allowedEffects = this._unique(
            (plan.allowed_effects || []).map(item =>
                labels.effectLabel ? labels.effectLabel(item) : item
            )
        );
        const actualTools = this._unique(tools.map(node => node.tool_base_name || node.label || node.id));
        const egressState = egressNodes.length
            ? `存在 ${egressNodes.length} 个外发节点`
            : '未发生外部外发';
        const summaryText = blocked
            ? (blocked.reason || blocked.block_reason || '策略阻断')
            : taskIncomplete
                ? (taskState.reason || taskState.outcome_summary || '必需结果未完成')
            : advisory
                ? (advisory.reason || '不可信数据影响了控制参数')
                : mitigated
                    ? (mitigated.reason || '检测到间接注入并对高风险文本执行隔离')
                : '敏感数据读取与外发行为均在本次任务授权范围内。';
        const rawOutcomeChecks = Array.isArray(
            taskState?.completion_audit?.outcomes
        )
            ? taskState.completion_audit.outcomes
            : [];
        const outcomeCounts = {
            satisfied: rawOutcomeChecks.filter(item =>
                String(item.status || '') === 'satisfied'
            ).length,
            unsatisfied: rawOutcomeChecks.filter(item =>
                String(item.status || '') === 'unsatisfied'
            ).length,
            uncertain: rawOutcomeChecks.filter(item =>
                String(item.status || '') === 'uncertain'
            ).length,
        };
        const auditKind = blocked
            ? 'blocked'
            : taskIncomplete
                ? 'incomplete'
                : advisory || mitigated
                    ? (mitigated ? 'mitigated' : 'advisory')
                    : 'completed';
        const localizedSummaryText = labels.auditSummaryText
            ? labels.auditSummaryText(auditKind, null, outcomeCounts)
            : '审计状态已记录。';
        const forbiddenEffects = this._unique(
            (plan.forbidden_effects || []).map(item =>
                labels.effectLabel ? labels.effectLabel(item) : item
            )
        );
        const stopConditions = Array.isArray(plan.stop_conditions)
            ? plan.stop_conditions
            : [];
        const outcomeChecks = Array.isArray(
            taskState?.completion_audit?.outcomes
        )
            ? taskState.completion_audit.outcomes.map(item => {
                const status = String(item.status || 'uncertain');
                const label = {
                    satisfied: '已完成',
                    unsatisfied: '未完成',
                    uncertain: '未验证',
                }[status] || status;
                return `${label}: ${item.description || item.id || ''}`;
            })
            : [];

        const localizedOutcomeChecks = rawOutcomeChecks.map(item => {
            const status = String(item.status || 'uncertain');
            const label = {
                satisfied: '已完成',
                unsatisfied: '未完成',
                uncertain: '未验证',
            }[status] || '未验证';
            const description = labels.hasChinese
                && labels.hasChinese(item.description)
                ? item.description
                : '';
            return `${label} · ${description || item.id || '必需结果'}`;
        });
        const stopConditionChecks = stopConditions.map((item, index) => {
            const behavior = labels.planBehaviorLabel
                ? labels.planBehaviorLabel(item.behavior)
                : '';
            const condition = labels.hasChinese
                && labels.hasChinese(item.when)
                ? item.when
                : `停止条件 ${index + 1}`;
            return behavior ? `${condition} · ${behavior}` : condition;
        });
        const categoryLabels = categories.map(item =>
            labels.categoryLabel ? labels.categoryLabel(item) : item
        );
        const promptNode = nodes.find(node => node.type === 'Prompt');
        const taskInstruction = promptNode?.content
            || (!labels.hasChinese || labels.hasChinese(plan.task_goal)
                ? plan.task_goal
                : '');
        const planActions = (plan.steps || [])
            .flatMap(step => step.actions || [])
            .filter(Boolean);
        const dataAccessActions = planActions
            .filter(action => action.data_access);
        const visibleFields = [...new Set(
            dataAccessActions.flatMap(
                action => action.data_access.visible_fields || []
            )
        )];
        const resourceScopes = [...new Set(planActions.flatMap(action => {
            const dataAccess = action.data_access || {};
            const resourceAccess = action.resource_access || dataAccess;
            return [
                ...(action.data_access
                    ? [`max: ${dataAccess.max_exposure_level || 'internal'}`]
                    : []),
                ...Object.entries(resourceAccess.resource_parameters || {})
                    .map(([name, rule]) => {
                        if (rule.mode === 'literal') {
                            return `${name}: ${(rule.allowed_values || []).join(', ')}`;
                        }
                        return `${name}: derived`;
                    })
            ];
        }))];
        const quarantineMetrics = tools
            .map(tool => tool.quarantine_metrics)
            .filter(metric => metric && metric.fields_measured);
        const quarantineSummary = quarantineMetrics.length
            ? [
                `覆盖率 ${Math.round(
                    Math.min(...quarantineMetrics.map(
                        metric => Number(metric.replacement_coverage || 0)
                    )) * 100
                )}%`,
                `隔离跨度 ${quarantineMetrics.reduce(
                    (sum, metric) => sum + Number(metric.redacted_spans_total || 0),
                    0
                )}`,
                quarantineMetrics.some(metric => metric.sanitized_residual_suspected)
                    ? '复扫仍有风险'
                    : '复扫通过',
            ]
            : [];

        const chips = (items, className = '') => items.length
            ? items.map(item => `<span class="audit-chip ${className}">${this._escape(item)}</span>`).join('')
            : '<span class="audit-muted">未声明</span>';

        body.innerHTML = `
            ${taskInstruction ? `
            <div class="audit-section">
                <span class="audit-block-label">任务指令原文</span>
                <div class="audit-goal">${this._escape(taskInstruction)}</div>
            </div>` : ''}
            <div class="audit-route">
                <span class="audit-block-label">跨 APP 路径</span>
                <div class="audit-route-flow">${route.length
                    ? route.map((app, index) => `
                        ${index ? '<span class="audit-route-arrow">→</span>' : ''}
                        <span class="audit-route-app app-${this._escape(app)}">${this._escape(this._appLabel(app))}</span>
                    `).join('')
                    : '<span class="audit-muted">暂无跨 APP 调用</span>'}</div>
            </div>
            <div class="audit-kpis">
                <div class="audit-kpi"><b>${tools.length}</b><span>工具调用</span></div>
                <div class="audit-kpi"><b>${route.length}</b><span>APP 域</span></div>
                <div class="audit-kpi"><b>${sensitive.length}</b><span>敏感数据</span></div>
                <div class="audit-kpi"><b>${untrusted.length}</b><span>不可信数据</span></div>
                <div class="audit-kpi"><b>${injectionFlagged.length}</b><span>注入 / 扫描异常</span></div>
            </div>
            <div class="audit-section">
                <span class="audit-block-label">授权工具</span>
                <div class="audit-chips">${chips(allowedActions, 'authorized')}</div>
            </div>
            <div class="audit-section">
                <span class="audit-block-label">实际调用</span>
                <div class="audit-chips">${chips(actualTools, 'actual')}</div>
            </div>
            <div class="audit-section audit-two-col">
                <div>
                    <span class="audit-block-label">Agent 可见字段</span>
                    <div class="audit-chips">${chips(visibleFields, 'sensitive')}</div>
                </div>
                <div>
                    <span class="audit-block-label">资源访问范围</span>
                    <div class="audit-chips">${chips(resourceScopes, 'effect')}</div>
                </div>
            </div>
            ${quarantineSummary.length ? `
            <div class="audit-section">
                <span class="audit-block-label">注入隔离指标</span>
                <div class="audit-chips">${chips(quarantineSummary, 'effect')}</div>
            </div>` : ''}
            <div class="audit-section audit-two-col">
                <div>
                    <span class="audit-block-label">数据类别</span>
                    <div class="audit-chips">${chips(categoryLabels, 'sensitive')}</div>
                </div>
                <div>
                    <span class="audit-block-label">操作效果</span>
                    <div class="audit-chips">${chips(allowedEffects, 'effect')}</div>
                </div>
            </div>
            <div class="audit-section audit-two-col">
                <div>
                    <span class="audit-block-label">禁止操作效果</span>
                    <div class="audit-chips">${chips(forbiddenEffects, 'forbidden')}</div>
                </div>
                <div>
                    <span class="audit-block-label">停止条件</span>
                    <div class="audit-chips">${chips(stopConditionChecks, 'effect')}</div>
                </div>
            </div>
            ${localizedOutcomeChecks.length ? `
            <div class="audit-section">
                <span class="audit-block-label">结果核验</span>
                <div class="audit-chips">${chips(localizedOutcomeChecks, 'effect')}</div>
            </div>` : ''}
            <div class="audit-verdict ${statusClass}">
                <span class="audit-verdict-icon">${blocked || taskIncomplete ? '!' : advisory ? '△' : '✓'}</span>
                <span>${this._escape(localizedSummaryText)}</span>
            </div>
            <div class="audit-footer">
                <span>${this._escape(egressState)}</span>
                <span>${sensitive.length ? '敏感内容已标记，审计视图保留完整证据' : '未检测到高敏数据'}</span>
                <span>${plan.plan_hash ? `计划哈希：${this._escape(plan.plan_hash)}` : '计划哈希：未生成'}</span>
            </div>
        `;
    },

    _latestPlan(tools) {
        for (let index = tools.length - 1; index >= 0; index -= 1) {
            const plan = tools[index].task_data_plan;
            if (plan && typeof plan === 'object') return plan;
        }
        return {};
    },

    _crossAppRoute(tools, graph) {
        if (graph && graph._rows && Array.isArray(graph._rows)) {
            const route = [];
            graph._rows.forEach(row => {
                if (!row.tool) return;
                const app = graph._canonicalApp(row.tool);
                if (app && app !== 'system' && app !== 'unknown' && route[route.length - 1] !== app) {
                    route.push(app);
                }
            });
            if (route.length) return route;
        }
        const route = [];
        tools.forEach(tool => {
            const app = graph && graph._canonicalApp
                ? graph._canonicalApp(tool)
                : (tool.app || 'unknown');
            if (app && app !== 'system' && app !== 'unknown' && route[route.length - 1] !== app) {
                route.push(app);
            }
        });
        return route;
    },

    _isSensitive(node) {
        const level = String(node?.flow_label?.confidentiality?.level || '').toLowerCase();
        const categories = node?.flow_label?.confidentiality?.categories || [];
        return Boolean(
            node?.is_sensitive
            || level === 'confidential'
            || level === 'secret'
            || categories.length
        );
    },

    _isUntrusted(node) {
        const kind = String(node?.flow_label?.integrity?.kind || '').toLowerCase();
        return kind === 'untrusted' || kind === 'tainted';
    },

    _isInjectionRisky(node) {
        const injection = node?.flow_label?.injection || {};
        return Boolean(
            injection.source_flagged
            || injection.incomplete
            || injection.available === false
            || (injection.risky_entities || []).length
            || (injection.quarantined_fields || []).length
        );
    },

    _categories(nodes) {
        const values = new Set();
        nodes.forEach(node => {
            const categories = node?.flow_label?.confidentiality?.categories || [];
            categories.forEach(category => values.add(String(category)));
        });
        return [...values].sort();
    },

    _unique(items) {
        return [...new Set(items.map(item => String(item || '').trim()).filter(Boolean))];
    },

    _appLabel(app) {
        return window.AgentTraceAppCatalog.appLabel(app);
    },

    _escape(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    },
};
