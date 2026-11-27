/**
 * Task-level audit summary derived from the rendered PROV graph.
 * It presents authorization scope, cross-APP route, sensitivity and policy
 * outcome without duplicating the complete graph or risk-card list.
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
        const categories = this._categories([...dataNodes, ...tools]);
        const egressNodes = nodes.filter(node =>
            node.type === 'EgressSink'
            || (node.type === 'AgentTool' && node.egress)
        );
        const blockedEvents = decisions.filter(node =>
            String(node.decision || '').toUpperCase() === 'BLOCK'
        );
        const advisory = decisions.find(node =>
            String(node.decision || '').toUpperCase() === 'ADVISORY'
        );
        const mitigated = decisions.find(node =>
            String(node.decision || '').toUpperCase() === 'MITIGATE'
        );
        const quarantinedEvent = decisions.find(node =>
            String(node.decision || '').toUpperCase() === 'QUARANTINE'
        );
        const taskState = [...nodes].reverse().find(node =>
            node.type === 'TaskState'
            && node.scope === 'task'
            && node.terminal === true
        );
        const taskOutcome = String(taskState?.state || '').toUpperCase();
        const hasTaskOutcome = Boolean(taskOutcome);
        const completionAssessed = (
            taskState?.completion_audit?.assessed === true
        );
        const taskBlocked = taskOutcome === 'BLOCKED';
        const taskQuarantined = [
            'QUARANTINED',
            'SANITIZED',
        ].includes(taskOutcome);
        const taskHeld = taskOutcome === 'HELD';
        const taskIncomplete = [
            'INCOMPLETE',
            'FAILED',
            'CANCELLED',
        ].includes(taskOutcome);
        const taskCompleted = taskOutcome === 'COMPLETED';

        let statusClass = '';
        let statusText = '等待任务';
        let auditKind = 'waiting';
        if (taskBlocked) {
            statusClass = 'blocked';
            statusText = '已阻断';
            auditKind = 'blocked';
        } else if (taskQuarantined) {
            statusClass = 'warning';
            statusText = '内容已隔离';
            auditKind = 'quarantined';
        } else if (taskHeld) {
            statusClass = 'warning';
            statusText = '等待人工决策';
            auditKind = 'held';
        } else if (taskIncomplete) {
            statusClass = 'warning';
            statusText = '任务未完成';
            auditKind = 'incomplete';
        } else if (taskCompleted) {
            auditKind = 'completed';
            if (!completionAssessed) {
                statusClass = 'warning';
                statusText = '结果待核验';
                auditKind = 'unverified';
            } else if (
                blockedEvents.length
                || advisory
                || mitigated
                || quarantinedEvent
            ) {
                statusClass = 'warning';
                statusText = '已完成（含风险）';
            } else {
                statusClass = 'ok';
                statusText = '检查通过';
            }
        } else if (blockedEvents.length) {
            statusClass = 'blocked';
            statusText = '已阻断';
            auditKind = 'blocked';
        } else if (advisory || mitigated) {
            statusClass = 'warning';
            statusText = mitigated ? '已隔离风险' : '存在提醒';
            auditKind = mitigated ? 'mitigated' : 'advisory';
        } else if (tools.length || hasTaskOutcome) {
            statusClass = 'warning';
            statusText = '结果待核验';
            auditKind = 'unverified';
        }

        statusEl.className = [
            'audit-summary-status',
            statusClass,
        ].filter(Boolean).join(' ');
        statusEl.textContent = statusText;
        const statusIcon = statusClass === 'ok'
            ? '✓'
            : statusClass === 'blocked'
                ? '!'
                : statusClass === 'warning'
                    ? '△'
                    : '·';

        const allowedActions = this._unique(plan.allowed_actions || []);
        const actualTools = this._unique(tools.map(node => node.tool_base_name || node.label || node.id));
        const unexpectedTools = allowedActions.length
            ? actualTools.filter(item => !allowedActions.includes(item))
            : [];
        const unusedAllowedTools = actualTools.length
            ? allowedActions.filter(item => !actualTools.includes(item))
            : [];
        const externalActions = egressNodes.reduce((items, node) => {
            const action = node.tool_base_name || node.label || node.id;
            return action && !items.includes(action)
                ? [...items, action]
                : items;
        }, []);
        const rawOutcomeChecks = Array.isArray(
            taskState?.completion_audit?.outcomes
        )
            ? taskState.completion_audit.outcomes
            : [];
        const rawDeterministicChecks = Array.isArray(
            taskState?.completion_audit
                ?.deterministic_evaluation_checks
        )
            ? taskState.completion_audit
                .deterministic_evaluation_checks
            : [];
        const requiredResultFailures = rawDeterministicChecks.filter(
            item => (
                item?.passed !== true
                && item?.category !== 'unexpected_change'
                && item?.name
                    !== 'no collateral application changes'
            )
        );
        const unexpectedChangeFailures = rawDeterministicChecks.filter(
            item => (
                item?.passed !== true
                && (
                    item?.category === 'unexpected_change'
                    || item?.name
                        === 'no collateral application changes'
                )
            )
        );
        const outcomeCounts = {
            satisfied: rawOutcomeChecks.filter(item =>
                String(item.status || '') === 'satisfied'
            ).length,
            unsatisfied: (
                rawOutcomeChecks.filter(item =>
                    String(item.status || '') === 'unsatisfied'
                ).length
                + requiredResultFailures.length
            ),
            uncertain: rawOutcomeChecks.filter(item =>
                String(item.status || '') === 'uncertain'
            ).length,
            unexpected: unexpectedChangeFailures.length,
        };
        const localizedSummaryText = labels.auditSummaryText
            ? labels.auditSummaryText(auditKind, null, outcomeCounts)
            : '审计状态已记录。';
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
        const localizedDeterministicChecks = rawDeterministicChecks.map(
            item => {
                const passed = item?.passed === true;
                const label = passed ? '通过' : '未通过';
                const name = this._deterministicCheckLabel(
                    item?.name
                );
                const detail = (
                    labels.hasChinese
                    && labels.hasChinese(item?.detail)
                )
                    ? item.detail
                    : '';
                return `${label} · ${detail || name}`;
            }
        );
        const businessGoalZh = String(
            taskState?.completion_audit?.business_goal_zh
            || ''
        ).trim();
        const noRequiredFailures = (
            requiredResultFailures.length === 0
        );
        const noUnexpectedChanges = (
            unexpectedChangeFailures.length === 0
        );
        let resultChecks = [];
        if (!completionAssessed && !rawDeterministicChecks.length) {
            resultChecks = [
                '未执行确定性真值核验，无法自动判断业务目标是否实现',
            ];
        } else if (
            taskCompleted
            && noRequiredFailures
            && noUnexpectedChanges
        ) {
            resultChecks = [
                businessGoalZh
                    ? `已实现 · ${businessGoalZh}`
                    : '正常任务要求已全部实现',
            ];
        } else {
            if (requiredResultFailures.length) {
                const labels = requiredResultFailures.map(item => (
                    this._deterministicCheckLabel(item.name)
                ));
                resultChecks.push(
                    `正常任务要求未实现 · ${this._unique(labels).join('；')}`
                );
            }
            unexpectedChangeFailures.forEach(item => {
                const detail = this._unexpectedChangeDetail(item.detail);
                resultChecks.push(
                    `额外环境变化 · ${detail || '存在任务范围外的应用状态变化'}`
                );
            });
            if (
                !resultChecks.length
                && !localizedOutcomeChecks.length
            ) {
                resultChecks.push(
                    taskCompleted
                        ? '正常任务要求已实现'
                        : '正常任务要求未全部实现'
                );
            }
        }
        if (!rawDeterministicChecks.length) {
            resultChecks = this._unique([
                ...localizedOutcomeChecks,
            ]);
        } else if (!taskCompleted) {
            resultChecks = this._unique([
                ...resultChecks,
                ...localizedOutcomeChecks,
            ]);
        }
        const categoryLabels = this._unique(
            categories
                .filter(item => !/^unknown(?:_|$)/i.test(item))
                .map(item =>
                    labels.categoryLabel
                        ? labels.categoryLabel(item)
                        : item
                )
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
        const visibleFields = this._unique(
            dataAccessActions.flatMap(
                action => action.data_access.visible_fields || []
            ).map(field => this._fieldName(field))
        );
        const exposureLevels = this._unique(
            dataAccessActions.map(
                action => action.data_access.max_exposure_level
            ).filter(Boolean)
        );
        const exposureRank = {
            public: 0,
            internal: 1,
            confidential: 2,
            secret: 3,
        };
        const highestExposure = exposureLevels.sort((left, right) => (
            (exposureRank[String(left).toLowerCase()] ?? -1)
            - (exposureRank[String(right).toLowerCase()] ?? -1)
        )).at(-1);
        const resourceScopes = this._unique(planActions.flatMap(action => {
            const dataAccess = action.data_access || {};
            const resourceAccess = action.resource_access || dataAccess;
            return [
                ...(action.data_access && highestExposure
                    ? [`最高读取等级：${highestExposure}`]
                    : []),
                ...Object.entries(resourceAccess.resource_parameters || {})
                    .map(([name, rule]) => {
                        if (rule.mode === 'literal') {
                            const values = (rule.allowed_values || []).join(', ');
                            return `${name}: ${values || '固定值'}`;
                        }
                        return `${name}: 由来源确定`;
                    })
            ];
        }));
        const quarantineMetrics = tools
            .map(tool => tool.quarantine_metrics)
            .filter(metric => metric && metric.fields_measured);
        const quarantinedSpans = quarantineMetrics.reduce(
            (sum, metric) => (
                sum + Number(metric.redacted_spans_total || 0)
            ),
            0
        );
        const quarantineResidual = quarantineMetrics.some(
            metric => metric.sanitized_residual_suspected
        );
        const quarantineSummary = quarantinedSpans || quarantineResidual
            ? [
                ...(quarantinedSpans
                    ? [`已隔离 ${quarantinedSpans} 处风险片段`]
                    : []),
                quarantineResidual
                    ? '隔离后复扫仍有风险'
                    : '隔离后复扫通过',
            ]
            : [];

        const chips = (items, className = '') => items.length
            ? items.map(item => `<span class="audit-chip ${className}">${this._escape(item)}</span>`).join('')
            : '';

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
                <div class="audit-kpi"><b>${externalActions.length}</b><span>外部外发</span></div>
            </div>
            ${(unexpectedTools.length || unusedAllowedTools.length) ? `
            <div class="audit-section audit-two-col">
                ${unexpectedTools.length ? `
                <div>
                    <span class="audit-block-label">计划外调用</span>
                    <div class="audit-chips">${chips(unexpectedTools, 'forbidden')}</div>
                </div>` : ''}
                ${unusedAllowedTools.length ? `
                <div>
                    <span class="audit-block-label">未执行授权工具</span>
                    <div class="audit-chips">${chips(unusedAllowedTools, 'authorized')}</div>
                </div>` : ''}
            </div>` : ''}
            ${actualTools.length ? `
            <div class="audit-section">
                <span class="audit-block-label">实际调用</span>
                <div class="audit-chips">${chips(actualTools, 'actual')}</div>
            </div>` : ''}
            ${(visibleFields.length || resourceScopes.length) ? `
            <div class="audit-section audit-two-col">
                ${visibleFields.length ? `
                <div>
                    <span class="audit-block-label"
                          title="任务计划允许 Agent 从工具结果中读取的数据字段；未列出的字段会被隐藏。">
                        Agent 可读取字段
                    </span>
                    <div class="audit-chips">${chips(visibleFields, 'sensitive')}</div>
                </div>` : ''}
                ${resourceScopes.length ? `
                <div>
                    <span class="audit-block-label">资源访问范围</span>
                    <div class="audit-chips">${chips(resourceScopes, 'effect')}</div>
                </div>` : ''}
            </div>` : ''}
            ${quarantineSummary.length ? `
            <div class="audit-section">
                <span class="audit-block-label">注入内容隔离</span>
                <div class="audit-chips">${chips(quarantineSummary, 'effect')}</div>
            </div>` : ''}
            ${categoryLabels.length ? `
            <div class="audit-section">
                <span class="audit-block-label">数据类别</span>
                <div class="audit-chips">${chips(categoryLabels, 'sensitive')}</div>
            </div>` : ''}
            ${resultChecks.length ? `
            <div class="audit-section">
                <span class="audit-block-label">结果核验</span>
                <div class="audit-chips">${chips(resultChecks, 'effect')}</div>
            </div>` : ''}
            <div class="audit-verdict ${statusClass}">
                <span class="audit-verdict-icon">${statusIcon}</span>
                <span>${this._escape(localizedSummaryText)}</span>
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

    _categories(nodes) {
        const values = new Set();
        nodes.forEach(node => {
            const categories = node?.flow_label?.confidentiality?.categories || [];
            categories.forEach(category => values.add(String(category)));
        });
        return [...values].sort();
    },

    _fieldName(value) {
        const parts = String(value || '')
            .replace(/\[\*\]|\[\d+\]/g, '')
            .split('.')
            .filter(part => part && part !== '$' && part !== '*');
        return parts.length ? parts[parts.length - 1] : '';
    },

    _deterministicCheckLabel(name) {
        const value = String(name || '').trim();
        const labels = {
            'no collateral application changes': '无任务范围外的应用变更',
            'one overdue-request reminder per coworker': '每位同事仅收到一条逾期提醒',
            'one transfer for the utility bill': '账单仅执行一笔转账',
            'one confirmation to Bob': '仅向 Bob 发送一条确认消息',
            'invoice confirmation': '发票确认结果正确',
            'hotel booking confirmation': '酒店预订结果正确',
            'Paris hotel reservation': '巴黎酒店预订结果正确',
            'Paris restaurant reservation': '巴黎餐厅预订结果正确',
            'Paris electric car reservation': '巴黎电动汽车预订结果正确',
        };
        return labels[value] || value || '确定性任务检查';
    },

    _unexpectedChangeDetail(detail) {
        return String(detail || '')
            .replace(
                /^One or more applications changed outside allowed_mutations:\s*/i,
                ''
            )
            .trim();
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
