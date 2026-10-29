/**
 * 拓扑图模块 - 使用 D3.js 渲染 PROV 知识图谱（结构化布局）
 *
 * 功能：
 * - 结构化布局：提示词 → 智能体 → 推理 → 输入数据 → 工具调用 → 输出数据
 * - 卡片式节点：类型 / 标题 / 摘要分层展示
 * - 列标题与迭代轮次（R1、R2…）引导
 * - 主信息流与审计边分层展示、关系分色、悬停聚焦关联路径
 * - 单条平滑 S 曲线动态避障，并通过边缘端口和曲率分散重叠边
 * - 拖拽、缩放、平移、自适应画布
 * - 点击查看详情
 */

const GRAPH = {
    // D3 相关
    svg: null,
    simulation: null,
    g: null,
    defs: null,

    // 数据
    nodes: [],
    links: [],

    // 节点 ID → 节点对象的 Map，确保引用一致性
    nodeMap: new Map(),

    // 行号映射（node id → 迭代行下标），用于行间不连线过滤
    _nodeRow: new Map(),

    // 当前图谱所属 suite（用于兼容旧 trace 的模块级 app 名）
    _contextSuite: null,
    _renderedNodes: null,
    _renderedLinks: null,
    _hiddenNodeFilters: new Set(),
    _routeObstacles: [],

    // 配置
    config: {
        width: 0,
        height: 0,
        showLabels: true,
        linkMode: 'flow',
        maxCardWidth: 360,
        primaryLinkRelations: [
            'used',
            'produces',
            'wasDerivedFrom',
            'risk_of',
            'policy_of',
            'egress_to',
            'authorizes',
        ],
        typeLabels: {
            'PolicyEvent': 'Policy event',
            'AIAgent': '智能体',
            'AIModelInvocation': 'LLM 推理',
            'AgentTool': '工具调用',
            'Prompt': '用户提示',
            'DomainData': '数据实体',
            'TaskState': 'FSM 状态',
            'RiskEvent': '风险事件',
            'EgressSink': '外部出口',
            'HumanAuthorization': '人工授权',
        },
        // APP 域 = 四个 TaskSuite（banking / workspace / slack / travel）
        appColors: {
            'system': '#6e7b8a',
            'unified': '#6e7b8a',
            'banking': '#3fb950',
            'workspace': '#4f8cff',
            'slack': '#a371f7',
            'travel': '#e3b341',
        },
        suiteLabels: {
            'banking': '银行套件',
            'workspace': '办公套件',
            'slack': '通讯套件',
            'travel': '旅行套件',
        },
        nodeColors: {
            'PolicyEvent': '#2ea043',
            'AIAgent': '#4f8cff',
            'AIModelInvocation': '#3fb950',
            'AgentTool': '#d4862b',
            'Prompt': '#d29922',
            'DomainData': '#a371f7',
            'TaskState': '#58a6ff',
            'RiskEvent': '#f85149',
            'EgressSink': '#f0883e',
            'HumanAuthorization': '#f0b429',
        },
        linkColors: {
            'policy_of': '#2ea043',
            'informed': '#3fb950',
            'used': '#d4862b',
            'produces': '#a371f7',
            'wasDerivedFrom': '#f85149',
            // 旧版兼容（保留但不再使用）
            'wasInformedBy': '#3fb950',
            'wasGeneratedBy': '#a371f7',
            'transition_from': '#58a6ff',
            'transition_to': '#58a6ff',
            'risk_of': '#f85149',
            'risk_evidence': '#f85149',
            'source_of': '#f0883e',
            'leak_sink': '#f0883e',
            'egress_to': '#f0883e',
            'authorizes': '#f0b429',
        },
        // 关系的中文标签
        relationLabels: {
            'informed': '通知',
            'used': '读取',
            'produces': '产出',
            'wasDerivedFrom': '派生',
            'transition_from': '转移自',
            'transition_to': '转移到',
            'risk_of': '风险关联',
            'risk_evidence': '风险证据',
            'source_of': '风险来源',
            'leak_sink': '泄漏出口',
            'policy_of': '策略判定',
            'egress_to': '外发到',
            'authorizes': '人工授权',
            // 旧版兼容
            'wasInformedBy': '通知',
            'wasGeneratedBy': '产出',
        },
    },

    /**
     * 初始化拓扑图
     */
    init() {
        const container = document.getElementById('graph-container');
        this.config.width = container.clientWidth;
        this.config.height = container.clientHeight;

        this.svg = d3.select('#graph-svg')
            .attr('width', this.config.width)
            .attr('height', this.config.height);

        // 添加 defs（用于渐变、滤镜等）
        this.defs = this.svg.append('defs');
        this._addDefs();

        // 添加缩放行为（保存实例，供重置/定位时复用）
        this.zoomBehavior = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                this.g && this.g.attr('transform', event.transform);
            });
        this.svg.call(this.zoomBehavior);

        this.g = this.svg.append('g');

        // 力导向模拟（节点位置由结构化布局固定，仅用于 tick 更新与拖拽）
        this.simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(180))
            .force('charge', d3.forceManyBody().strength(-500))
            .force('center', d3.forceCenter(this.config.width / 2, this.config.height / 2))
            .force('collision', d3.forceCollide().radius(55));

        // 窗口大小变化时更新
        window.addEventListener('resize', () => {
            this.config.width = container.clientWidth;
            this.config.height = container.clientHeight;
            this.svg.attr('width', this.config.width).attr('height', this.config.height);
            this.simulation.force('center', d3.forceCenter(this.config.width / 2, this.config.height / 2));
            if (this.nodes.length > 0) {
                this.render();
            }
        });

        // 绑定控制按钮
        document.getElementById('btnReset').addEventListener(
            'click',
            () => this.resetLayout(),
        );
        document.getElementById('chkShowLabels').addEventListener('change', (e) => {
            this.config.showLabels = e.target.checked;
            this.updateLabels();
        });
        document.getElementById('chkShowAuditEdges').addEventListener('change', (e) => {
            this.config.linkMode = e.target.checked ? 'audit' : 'flow';
            if (this.nodes.length > 0) {
                this.render();
                requestAnimationFrame(() => this.resetView());
            }
        });

        this._bindLegendControls();

    },

    _bindLegendControls() {
        const toggle = document.getElementById('btnToggleLegend');
        const legend = document.querySelector('.legend');
        if (toggle && legend) {
            toggle.addEventListener('click', () => {
                const collapsed = legend.classList.toggle('collapsed');
                toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
            });
        }

        document.querySelectorAll('[data-node-filter]').forEach((button) => {
            button.addEventListener('click', () => {
                this._toggleNodeFilter(button.dataset.nodeFilter);
            });
        });

        const reset = document.getElementById('btnResetNodeFilters');
        if (reset) {
            reset.addEventListener('click', () => this._resetNodeFilters());
        }
        this._syncNodeFilterLegend();
    },

    _toggleNodeFilter(filter) {
        const value = String(filter || '').trim();
        if (!value) return;
        if (this._hiddenNodeFilters.has(value)) {
            this._hiddenNodeFilters.delete(value);
        } else {
            this._hiddenNodeFilters.add(value);
        }
        this._syncNodeFilterLegend();
        this.render();
        requestAnimationFrame(() => this.resetView());
    },

    _resetNodeFilters() {
        if (this._hiddenNodeFilters.size === 0) return;
        this._hiddenNodeFilters.clear();
        this._syncNodeFilterLegend();
        this.render();
        requestAnimationFrame(() => this.resetView());
    },

    _syncNodeFilterLegend() {
        document.querySelectorAll('[data-node-filter]').forEach((button) => {
            const filter = button.dataset.nodeFilter;
            const hidden = this._hiddenNodeFilters.has(filter);
            button.setAttribute('aria-pressed', hidden ? 'true' : 'false');
            button.title = hidden
                ? '点击恢复该类节点'
                : '点击隐藏该类节点';
        });
        const status = document.getElementById('legendNodeStatus');
        if (status) {
            const count = this._hiddenNodeFilters.size;
            status.textContent = count > 0 ? `已隐藏 ${count} 类` : '';
        }
    },

    _nodeMatchesFilter(node, filter) {
        if (!node) return false;
        switch (filter) {
            case 'agent':
                return node.type === 'AIAgent';
            case 'llm':
                return node.type === 'AIModelInvocation';
            case 'tool':
                return node.type === 'AgentTool';
            case 'prompt':
                return node.type === 'Prompt';
            case 'data':
                return node.type === 'DomainData';
            case 'sensitive':
                return this._isSensitiveNode(node);
            case 'untrusted': {
                const kind = String(
                    ((node.flow_label || {}).integrity || {}).kind || ''
                ).toLowerCase();
                return kind === 'untrusted' || kind === 'tainted';
            }
            case 'risk': {
                const decision = String(
                    node.decision || node.risk_decision || ''
                ).toLowerCase();
                const state = String(node.state || '').toUpperCase();
                return node.type === 'RiskEvent'
                    || node.type === 'PolicyEvent'
                    || node.blocked === true
                    || ['block', 'quarantine', 'hold'].includes(decision)
                    || ['BLOCKED', 'QUARANTINED', 'HELD', 'FAILED'].includes(state);
            }
            case 'authorization':
                return node.type === 'HumanAuthorization';
            default:
                return false;
        }
    },

    _filteredGraphData() {
        const filters = [...this._hiddenNodeFilters];
        const nodes = filters.length === 0
            ? this.nodes
            : this.nodes.filter((node) => !filters.some(
                (filter) => this._nodeMatchesFilter(node, filter)
            ));
        const nodeIds = new Set(nodes.map((node) => node.id));
        const links = this.links.filter((link) => {
            const sourceId = link.source && typeof link.source === 'object'
                ? link.source.id
                : link.source;
            const targetId = link.target && typeof link.target === 'object'
                ? link.target.id
                : link.target;
            return nodeIds.has(sourceId) && nodeIds.has(targetId);
        });
        return { nodes, links };
    },

    /**
     * 添加 SVG defs（箭头、滤镜）
     */
    _addDefs() {
        // 箭头定义
        const arrowTypes = Object.keys(this.config.linkColors);
        arrowTypes.forEach(type => {
            this.defs.append('marker')
                .attr('id', `arrow-${type}`)
                .attr('viewBox', '0 -5 10 10')
                .attr('refX', 10)
                .attr('refY', 0)
                .attr('markerWidth', 7)
                .attr('markerHeight', 7)
                .attr('orient', 'auto')
                .append('path')
                .attr('d', 'M0,-5L10,0L0,5')
                .attr('fill', this.config.linkColors[type] || '#5a6a7a');
        });

    },

    /**
     * 加载并渲染图谱数据
     */
    async loadData() {
        try {
            const data = await API.getGraphData();
            if (!data || !data.graph) {
                console.error('图谱数据为空');
                return;
            }

            this.setData(data.graph.nodes, data.graph.links, { suite: data.suite || null });
            this.render();

            // 加载风险卡片
            const riskCards = await RISK_PANEL.loadRiskCards();

            // 加载事件时间线
            TIMELINE.loadEvents(data.events);

            this.updateStats(
                data.summary,
                Array.isArray(riskCards) ? riskCards.length : 0,
                Array.isArray(data.events) ? data.events.length : undefined
            );

        } catch (err) {
            console.error('加载图谱数据失败:', err);
        }
    },

    /**
     * 设置数据，确保节点引用一致性
     */
    setData(newNodes, newLinks, context = {}) {
        this._contextSuite = context && context.suite ? context.suite : null;

        const terminalStates = new Set([
            'SANITIZED',
            'BLOCKED',
            'QUARANTINED',
            'HELD',
            'FAILED',
            'COMPLETED',
        ]);
        const displayedNodes = newNodes.filter(node => (
            node.type !== 'TaskState'
            || terminalStates.has(String(node.state || '').toUpperCase())
        ));
        const displayedIds = new Set(displayedNodes.map(node => node.id));
        const displayedLinks = newLinks.filter(link => {
            const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
            const targetId = typeof link.target === 'object' ? link.target.id : link.target;
            return displayedIds.has(sourceId) && displayedIds.has(targetId);
        });

        // 重建 nodeMap
        this.nodeMap = new Map();
        displayedNodes.forEach(n => this.nodeMap.set(n.id, n));

        // 确保 links 中的 source/target 引用 nodeMap 中的对象
        displayedLinks.forEach(link => {
            const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
            const targetId = typeof link.target === 'object' ? link.target.id : link.target;

            link.source = this.nodeMap.get(sourceId) || { id: sourceId, x: 0, y: 0 };
            link.target = this.nodeMap.get(targetId) || { id: targetId, x: 0, y: 0 };
        });

        this.nodes = displayedNodes;
        this.links = displayedLinks;

        console.log(`[graph] ${this.nodes.length} 节点, ${this.links.length} 边`);
    },

    /**
     * 生成节点的卡片化展示信息（类型 / 标题 / 摘要 / 尺寸）。
     */
    _prepareNodeViews(nodes = this.nodes, links = this.links) {
        const maxWidth = Math.max(140, Math.min(
            this.config.maxCardWidth,
            (this.config.width || 1200) * 0.38
        ));
        const thoughts = nodes.filter(n => n.type === 'AIModelInvocation');
        const thoughtIndex = new Map(thoughts.map((n, i) => [n.id, i + 1]));
        const producerByOutput = new Map();

        const idOf = (value) => (value && typeof value === 'object') ? value.id : value;

        links.forEach((link) => {
            if (link.relation !== 'produces') return;
            const source = this.nodeMap.get(idOf(link.source));
            const target = this.nodeMap.get(idOf(link.target));
            if (source && target && target.type === 'DomainData' && target.operation !== 'input') {
                producerByOutput.set(target.id, source);
            }
        });

        nodes.forEach((node) => {
            const riskLabels = window.AgentTraceRiskLabels;
            let typeName = this.config.typeLabels[node.type] || node.type;
            const displayRisk = node.type === 'AgentTool'
                ? node.tool_risk_level
                : node.risk_level;
            if (displayRisk) {
                typeName = `${displayRisk} · ${typeName}`;
            }
            const color = this.config.nodeColors[node.type] || '#6e7b8a';
            const canonicalApp = this._canonicalApp(node);
            const appText = canonicalApp && canonicalApp !== 'unknown'
                ? this._shortText(this._appLabel(canonicalApp), 8)
                : '';
            const appColor = this._appColor(canonicalApp);
            const suite = node.suite || this._contextSuite || '';
            const suiteLabel = this.config.suiteLabels[suite] || suite;
            let title = node.label || node.id || typeName;
            let subtitle = '';
            const flowLabel = node.flow_label || {};
            const confidentiality = flowLabel.confidentiality || {};
            const integrity = flowLabel.integrity || {};
            if (node.type === 'DomainData' || node.type === 'AgentTool') {
                const confidentialityLabels = {
                    public: '公开',
                    internal: '内部',
                    confidential: '私密',
                    secret: '机密',
                };
                const integrityLabels = {
                    trusted: '可信',
                    untrusted: '外部',
                    tainted: '污染',
                };
                const conf = riskLabels?.confidentialityLabel
                    ? riskLabels.confidentialityLabel(
                        confidentiality.level || ''
                    )
                    : (
                        confidentialityLabels[String(
                            confidentiality.level || ''
                        ).toLowerCase()] || ''
                    );
                const trust = riskLabels?.integrityLabel
                    ? riskLabels.integrityLabel(integrity.kind || '')
                    : (
                        integrityLabels[String(
                            integrity.kind || ''
                        ).toLowerCase()] || ''
                    );
                const badges = [conf, trust ? `I:${trust}` : ''].filter(Boolean);
                if (badges.length) typeName += ` · ${badges.join(' ')}`;
                if (this._isInjectionRisky(node)) {
                    typeName += this._hasDirectInjectionQuarantine(node)
                        ? ' · 注入隔离'
                        : ' · 来源可疑';
                }
            }

            if (node.type === 'AIAgent') {
                title = node.label || 'AIAgent';
                subtitle = '调度与决策中心';
            } else if (node.type === 'Prompt') {
                title = '用户指令';
                subtitle = this._shortText(node.label || node.id || '', 40);
            } else if (node.type === 'AIModelInvocation') {
                title = `推理 #${thoughtIndex.get(node.id) || '?'}`;
                const tools = links
                    .filter(l => idOf(l.source) === node.id && l.relation === 'informed')
                    .map(l => this.nodeMap.get(idOf(l.target)))
                    .filter(n => n && n.type === 'AgentTool')
                    .map(n => n.label || n.id);
                subtitle = tools.length > 0
                    ? tools.join(' · ')
                    : this._shortText(node.label || '', 40);
            } else if (node.type === 'AgentTool') {
                title = node.label || node.id;
                const controlCounts = { risk: 0, policy: 0, authorization: 0 };
                links.forEach((link) => {
                    if (idOf(link.target) !== node.id) return;
                    if (link.relation === 'risk_of') controlCounts.risk += 1;
                    if (link.relation === 'policy_of') controlCounts.policy += 1;
                    if (link.relation === 'authorizes') {
                        controlCounts.authorization += 1;
                    }
                });
                const controlSummary = [
                    controlCounts.risk ? `风险 ${controlCounts.risk}` : '',
                    controlCounts.policy ? `策略 ${controlCounts.policy}` : '',
                    controlCounts.authorization
                        ? `授权 ${controlCounts.authorization}`
                        : '',
                ].filter(Boolean);
                subtitle = [
                    node.module || node.app || '',
                    ...controlSummary,
                ].filter(Boolean).join(' · ');
            } else if (node.type === 'DomainData') {
                if (node.operation === 'input') {
                    title = '输入数据';
                    subtitle = this._formatDataLabel(node.label) || node.entity_type || '调用参数';
                } else if (node.operation === 'output') {
                    title = '工具结果';
                    const producer = producerByOutput.get(node.id);
                    subtitle = producer
                        ? `${producer.label || producer.id} 返回`
                        : (node.entity_type || '执行输出');
                } else if (
                    node.operation === 'created'
                    || node.operation === 'updated'
                    || node.operation === 'deleted'
                ) {
                    const operationLabel = {
                        created: '新增',
                        updated: '更新',
                        deleted: '删除',
                    }[node.operation];
                    title = `环境变更 · ${operationLabel}`;
                    subtitle = node.entity_type || this._formatDataLabel(node.label) || '';
                } else {
                    title = '数据实体';
                    subtitle = this._formatDataLabel(node.label) || node.entity_type || '';
                }
            } else if (node.type === 'TaskState') {
                title = riskLabels?.taskStateLabel
                    ? riskLabels.taskStateLabel(node.state || node.label)
                    : '任务状态';
                subtitle = this._taskStateDescription(node);
            } else if (node.type === 'RiskEvent' || node.type === 'PolicyEvent') {
                title = riskLabels
                    ? riskLabels.titleFor(
                        Number(node.ring == null ? 0 : node.ring),
                        String(node.policy_id || '')
                    )
                    : `Ring ${node.ring == null ? '?' : node.ring} · ${node.decision || 'RISK'}`;
                subtitle = this._riskNodeDetail(node) || '安全策略事件';
            } else if (node.type === 'EgressSink') {
                title = node.label || '外发出口';
                subtitle = '外部数据接收目标';
            } else if (node.type === 'HumanAuthorization') {
                const status = String(node.status || 'pending').toLowerCase();
                const statusLabel = this._authorizationStatusLabel(status);
                title = `人工授权 · ${statusLabel}`;
                subtitle = status === 'pending'
                    ? `点击节点处理 · ${node.tool_name || node.request_id || ''}`
                    : (node.tool_name || node.request_id || statusLabel);
            }

            const titleFont = node.type === 'AgentTool'
                ? '600 9.5px monospace'
                : '600 11px sans-serif';
            const subtitleFont = node.type === 'DomainData'
                ? '9.5px monospace'
                : '9px sans-serif';
            const typeWidth = this._measureText(
                typeName,
                '600 9px sans-serif',
                0.45,
            );
            const appWidth = appText
                ? this._measureText(
                    appText,
                    '600 8.5px sans-serif',
                    0.25,
                )
                : 0;
            const titleWidth = this._measureText(title, titleFont);
            const subtitleWidth = this._measureText(
                subtitle || '',
                subtitleFont,
            );
            const desiredWidth = Math.max(
                titleWidth,
                subtitleWidth,
                typeWidth + appWidth + 20,
            ) + 32;
            const width = Math.max(
                108,
                Math.min(maxWidth, Math.ceil(desiredWidth)),
            );
            const typeMaxWidth = Math.max(
                28,
                width - 30 - appWidth,
            );
            const viewType = this._truncateTextToWidth(
                typeName,
                typeMaxWidth,
                '600 9px sans-serif',
            );
            const viewTitle = this._truncateTextToWidth(
                title,
                width - 32,
                titleFont,
            );
            const viewSubtitle = this._truncateTextToWidth(
                subtitle || '',
                width - 32,
                subtitleFont,
            );

            node.__view = {
                title: viewTitle,
                subtitle: viewSubtitle,
                full: node.label || node.id || title,
                typeName,
                typeText: viewType,
                color,
                app: canonicalApp,
                module: node.module || (node.app && node.app !== canonicalApp ? node.app : ''),
                suite,
                suiteLabel,
                appText,
                appColor,
                width,
                height: 46,
            };
        });
    },

    _shortText(text, max) {
        const value = String(text == null ? '' : text).replace(/\s+/g, ' ').trim();
        return value.length > max ? `${value.slice(0, max)}…` : value;
    },

    _measureText(text, font, letterSpacing = 0) {
        const value = String(text == null ? '' : text);
        if (!value) return 0;
        if (!this._textMeasureContext && typeof document !== 'undefined') {
            this._textMeasureContext = document.createElement('canvas')
                .getContext('2d');
        }
        if (!this._textMeasureContext) {
            const size = Number(String(font).match(/(\d+(?:\.\d+)?)px/)?.[1])
                || 10;
            return value.length * size * 0.62 + value.length * letterSpacing;
        }
        this._textMeasureContext.font = font;
        return (
            this._textMeasureContext.measureText(value).width
            + value.length * letterSpacing
        );
    },

    _truncateTextToWidth(text, maxWidth, font) {
        const value = String(text == null ? '' : text)
            .replace(/\s+/g, ' ')
            .trim();
        if (
            !value
            || this._measureText(value, font)
            <= Math.max(1, maxWidth)
        ) {
            return value;
        }
        const ellipsis = '…';
        let low = 0;
        let high = value.length;
        while (low < high) {
            const mid = Math.ceil((low + high) / 2);
            const candidate = `${value.slice(0, mid)}${ellipsis}`;
            if (this._measureText(candidate, font) <= maxWidth) {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        return `${value.slice(0, Math.max(1, low))}${ellipsis}`;
    },

    _escapeHtml(text) {
        return String(text == null ? '' : text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    },

    /**
     * 将 Python 字典形式的参数标签转换为易读文本。
     */
    _formatDataLabel(label) {
        const text = String(label == null ? '' : label).trim();
        if (!text) return '';
        return this._shortText(
            text.replace(/[{}'"]/g, '').replace(/:\s*/g, ': ').replace(/,\s*/g, ' · '),
            40
        );
    },

    _relationClass(relation) {
        const map = {
            'belongsTo': 'belongs-to',
            'wasAssociatedWith': 'belongs-to',
            'wasAttributedTo': 'belongs-to',
            'informed': 'informed',
            'wasInformedBy': 'informed',
            'used': 'used',
            'produces': 'produces',
            'wasGeneratedBy': 'produces',
            'wasDerivedFrom': 'derived',
            'transition_from': 'belongs-to',
            'transition_to': 'belongs-to',
            'stateTransition': 'belongs-to',
            'risk_of': 'derived',
            'risk_evidence': 'derived',
            'leak_sink': 'derived',
            'authorizes': 'authorizes',
        };
        return map[relation] || 'other';
    },

    _nodeClass(node) {
        let cls = `node type-${String(node.type || 'unknown').toLowerCase()}`;
        if (node.blocked) cls += ' abnormal';
        if (this._isSensitiveNode(node)) cls += ' sensitive';
        if (this._isInjectionRisky(node)) {
            cls += this._hasDirectInjectionQuarantine(node)
                ? ' injection-flagged'
                : ' source-suspicious';
        }
        const decision = String(node.decision || node.risk_decision || '').toLowerCase();
        const severity = String(
            node.severity
            || (node.type === 'AgentTool' ? '' : node.risk_level)
            || ''
        ).toLowerCase();
        if (decision === 'block' || decision === 'quarantine' || severity === 'high') cls += ' risk-high';
        else if (decision === 'hold' || decision === 'mitigate' || severity === 'medium') cls += ' risk-medium';
        else if (decision === 'advisory' || severity === 'low') cls += ' risk-low';
        if (node.type === 'HumanAuthorization') {
            const status = String(node.status || 'pending').toLowerCase();
            cls += ` authorization-${status}`;
        }
        if (!this.config.showLabels) cls += ' label-hidden';
        return cls;
    },

    _authorizationStatusLabel(status) {
        const labels = {
            pending: '待确认',
            approved: '已批准',
            rejected: '已拒绝',
            expired: '已过期',
            cancelled: '已取消',
        };
        return labels[String(status || 'pending').toLowerCase()] || String(status || '待确认');
    },

    _localizedReason(value, fallback) {
        const labels = window.AgentTraceRiskLabels;
        const text = String(value || '').trim();
        return labels?.hasChinese?.(text) ? text : fallback;
    },

    _riskNodeDetail(node) {
        const labels = window.AgentTraceRiskLabels;
        if (!labels?.normalizeCard) return '';
        const normalized = labels.normalizeCard(node);
        return normalized.defense_detail || '';
    },

    _taskStateDescription(node) {
        const labels = window.AgentTraceRiskLabels;
        const state = String(node?.state || '').toUpperCase();
        const fallback = {
            COMPLETED: '任务已完成并通过终态记录。',
            INCOMPLETE: '任务已结束，但存在未完成的必需结果。',
            BLOCKED: '安全策略阻断了任务。',
            FAILED: '任务执行失败。',
            CANCELLED: '任务已取消。',
        }[state] || '任务状态已记录。';
        return this._localizedReason(node?.reason, fallback);
    },

    _isSensitiveNode(node) {
        if (!node) return false;
        if (node.is_sensitive) return true;
        const confidentiality = (node.flow_label || {}).confidentiality || {};
        const level = String(confidentiality.level || '').toLowerCase();
        const categories = Array.isArray(confidentiality.categories)
            ? confidentiality.categories
            : [];
        return level === 'confidential'
            || level === 'secret'
            || categories.length > 0;
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

    _hasDirectInjectionQuarantine(node) {
        const injection = node?.flow_label?.injection || {};
        return Boolean((injection.quarantined_fields || []).length);
    },

    _sensitiveDetailBlock(label, value, sensitive, long = false) {
        const rendered = window.AgentTraceContent
            ? window.AgentTraceContent.render(value)
            : this._escapeHtml(value);
        const sensitiveLabel = sensitive ? ' · 敏感审计内容' : '';
        return `<div class="detail-field">
            <span class="label">${this._escapeHtml(label)}${sensitiveLabel}</span>
            <div class="value${long ? ' detail-value-long' : ''}${sensitive ? ' sensitive-content' : ''}">${rendered}</div>
        </div>`;
    },

    _linkGroupClass(link) {
        let cls = `link-group link-${this._relationClass(link.relation)}`;
        if (link.__bundleHidden) cls += ' link-bundle-hidden';
        if (link.__contextHidden) cls += ' link-context-hidden';
        if (link.__bundlePrimary) cls += ' link-bundle-primary';
        if (link.__displayRelations?.length > 1) cls += ' link-merged-relations';
        if (this._isContextLink(link)) cls += ' link-context';
        if (this._isCrossAppLink(link)) cls += ' link-cross-app';
        if (this._isControlDependencyLink(link)) cls += ' link-control-dependency';
        return cls;
    },

    _isControlDependencyLink(link) {
        if (!link || link.relation !== 'informed' || !link.source || !link.target) {
            return false;
        }
        return (
            (link.source.type === 'DomainData' && link.target.type === 'AIModelInvocation')
            || (link.source.type === 'AIModelInvocation' && link.target.type === 'AgentTool')
            || (link.source.type === 'DomainData' && link.target.type === 'AgentTool')
        );
    },

    /**
     * APP 域配色：内置常用 APP，其余使用稳定哈希色。
     */
    _appColor(app) {
        const key = String(app == null ? '' : app).trim();
        if (!key || key === 'unknown') return '#6e7b8a';
        if (this.config.appColors[key]) return this.config.appColors[key];

        let hash = 0;
        for (let i = 0; i < key.length; i++) {
            hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
        }
        return `hsl(${hash % 360}, 52%, 62%)`;
    },

    _appLabel(app) {
        const key = String(app == null ? '' : app).trim();
        return window.AgentTraceAppCatalog.appLabel(key) || '未知';
    },

    /**
     * 把旧的模块级 app 名（file_reader/email/calendar 等）兼容为 suite 级 APP 域。
     */
    _canonicalApp(node) {
        const moduleName = String((node && node.module) || '').trim();
        const raw = String((node && node.app) || '').trim();
        const contextSuite = String((node && node.suite) || this._contextSuite || '').trim();

        return window.AgentTraceAppCatalog.canonicalApp(
            moduleName || raw,
            contextSuite
        ) || 'unknown';
    },

    /**
     * 判断一条因果边是否跨越 APP（归属边只表示隶属关系，不计入跨 APP 调用）。
     */
    _isCrossAppLink(link) {
        if (!link || !link.source || !link.target) return false;
        if (link.relation === 'belongsTo'
            || link.relation === 'wasAssociatedWith'
            || link.relation === 'wasAttributedTo') {
            return false;
        }

        const sourceApp = this._canonicalApp(link.source);
        const targetApp = this._canonicalApp(link.target);
        if (!sourceApp || !targetApp || sourceApp === 'unknown' || targetApp === 'unknown') {
            return false;
        }
        // system（智能体/提示词）不属于四个业务 APP，system ↔ APP 不计跨 APP
        if (sourceApp === 'system' || targetApp === 'system') {
            return false;
        }
        return sourceApp !== targetApp;
    },

    /**
     * 聚焦某个 APP 的全部节点与关联边。
     */
    _focusApp(app) {
        const ids = new Set(
            this.nodes.filter(n => this._canonicalApp(n) === app).map(n => n.id)
        );

        this.g.selectAll('.node')
            .classed('dimmed', n => !ids.has(n.id))
            .classed('focused', n => ids.has(n.id));

        this.g.selectAll('.link-group')
            .classed('dimmed', l => !(ids.has(l.source.id) || ids.has(l.target.id)))
            .classed('highlighted', l => ids.has(l.source.id) || ids.has(l.target.id));

        document.querySelectorAll('.app-flow-chip').forEach((chip) => {
            chip.setAttribute('aria-pressed', chip.dataset.app === app ? 'true' : 'false');
        });
    },

    /** Prompt → LLM 推理属于上下文传递，弱化显示 */
    _isContextLink(link) {
        return link
            && link.relation === 'informed'
            && link.source
            && link.source.type === 'Prompt';
    },

    _linkMarker(link) {
        if (!link || this._isContextLink(link)) return null;
        if (link.relation === 'belongsTo' || link.relation === 'wasAssociatedWith' || link.relation === 'wasAttributedTo') {
            return null;
        }
        return `url(#arrow-${link.relation})`;
    },

    _linkLabelText(link) {
        const displayRelations = link.__displayRelations || [];
        if (
            displayRelations.includes('risk_evidence')
            && displayRelations.includes('source_of')
        ) {
            return '风险证据 / 来源';
        }
        if (link.__bundlePrimary && Number(link.__bundleCount) > 1) {
            const label = link.relation === 'informed'
                ? '上下文'
                : (link.relation === 'produces' ? '产出' : '派生');
            return `${label} ×${link.__bundleCount}`;
        }
        const silentRelations = new Set([
            'stateTransition',
            'transition_from',
            'transition_to',
            'hasState',
            'contains',
            'belongsTo',
            'wasAssociatedWith',
            'wasAttributedTo',
        ]);
        if (silentRelations.has(link.relation)) return '';
        if (link.relation === 'informed') {
            if (link.source && link.target) {
                if (link.source.type === 'DomainData') return '数据影响';
                if (link.target.type === 'AgentTool') return '决策触发';
            }
            return '上下文';
        }
        const relation = this.config.relationLabels[link.relation] || link.relation;
        return this._isCrossAppLink(link) ? `跨 APP · ${relation}` : relation;
    },

    _prepareLinkRoutes(nodes, links) {
        const clearance = 8;
        this._routeObstacles = nodes.map((node) => {
            const view = node.__view || { width: 108, height: 46 };
            return {
                id: node.id,
                left: node.x - view.width / 2 - clearance,
                right: node.x + view.width / 2 + clearance,
                top: node.y - view.height / 2 - clearance,
                bottom: node.y + view.height / 2 + clearance,
            };
        });

        const outgoing = new Map();
        const incoming = new Map();
        links.forEach((link) => {
            const sourceId = link.source.id;
            const targetId = link.target.id;
            if (!outgoing.has(sourceId)) outgoing.set(sourceId, []);
            if (!incoming.has(targetId)) incoming.set(targetId, []);
            outgoing.get(sourceId).push(link);
            incoming.get(targetId).push(link);
        });
        const assignPortOffsets = (groups, sourceSide, field) => {
            groups.forEach((linksAtNode) => {
                const count = linksAtNode.length;
                linksAtNode.forEach((link, index) => {
                    if (count === 1) {
                        link[field] = 0;
                        return;
                    }
                    const node = sourceSide ? link.source : link.target;
                    const height = node.__view?.height || 46;
                    const span = Math.max(8, Math.min(28, height - 16));
                    link[field] = (index / (count - 1) - 0.5) * span;
                });
            });
        };
        assignPortOffsets(outgoing, true, '__sourcePortOffset');
        assignPortOffsets(incoming, false, '__targetPortOffset');

        const pairGroups = new Map();
        links.forEach((link) => {
            const key = `${link.source.id}\u0000${link.target.id}`;
            if (!pairGroups.has(key)) pairGroups.set(key, []);
            pairGroups.get(key).push(link);
        });
        const pairPositions = new Map();
        pairGroups.forEach((group) => {
            group.forEach((link, index) => {
                pairPositions.set(link, {
                    index,
                    count: group.length,
                });
            });
        });

        links.forEach((link, index) => {
            const pair = pairPositions.get(link);
            if (pair && pair.count > 1) {
                link.__curveSign = pair.index % 2 === 0 ? 1 : -1;
                link.__curveMagnitude = 10 + pair.index * 2;
            } else {
                const direction = Math.sign(
                    (link.target.y || 0) - (link.source.y || 0),
                );
                link.__curveSign = direction || (index % 2 === 0 ? 1 : -1);
                link.__curveMagnitude = 4 + (index % 3) * 2;
            }
        });

        const occupiedCurves = [];
        links.forEach((link) => {
            const curve = this._buildLinkCurve(link, occupiedCurves);
            link.__curvePath = curve.path;
            link.__curveSamples = curve.samples;
            link.__routePoints = [];
            link.__labelPoint = curve.labelPoint;
            occupiedCurves.push(curve.samples);
        });
    },

    _columnIndex(node) {
        if (!node || !this._columns.length) return -1;
        if (Number.isFinite(node.__columnIndex)) {
            return node.__columnIndex;
        }
        let bestIndex = 0;
        let bestDistance = Infinity;
        this._columns.forEach((column, index) => {
            const distance = Math.abs(Number(node.x) - column.x);
            if (distance < bestDistance) {
                bestDistance = distance;
                bestIndex = index;
            }
        });
        return bestIndex;
    },

    _sampleCubic(start, control1, control2, end, steps = 48) {
        const samples = [];
        for (let step = 0; step <= steps; step += 1) {
            const t = step / steps;
            const inverse = 1 - t;
            samples.push({
                x: inverse ** 3 * start.x
                    + 3 * inverse ** 2 * t * control1.x
                    + 3 * inverse * t ** 2 * control2.x
                    + t ** 3 * end.x,
                y: inverse ** 3 * start.y
                    + 3 * inverse ** 2 * t * control1.y
                    + 3 * inverse * t ** 2 * control2.y
                    + t ** 3 * end.y,
            });
        }
        return samples;
    },

    _curveHitsNode(link, samples) {
        return this._routeObstacles.some(box => (
            box.id !== link.source.id
            && box.id !== link.target.id
            && samples.some(point => (
                point.x > box.left
                && point.x < box.right
                && point.y > box.top
                && point.y < box.bottom
            ))
        ));
    },

    _curvesOverlap(firstSamples, secondSamples) {
        const first = firstSamples.slice(4, -4);
        const second = secondSamples.slice(4, -4);
        if (!first.length || !second.length) return false;
        let closeSamples = 0;
        first.forEach((point) => {
            const nearest = Math.min(...second.map(other => (
                Math.hypot(point.x - other.x, point.y - other.y)
            )));
            if (nearest < 1.2) closeSamples += 1;
        });
        return closeSamples >= 3;
    },

    _buildLinkCurve(link, occupiedCurves) {
        const sourceColumn = this._columnIndex(link.source);
        const targetColumn = this._columnIndex(link.target);
        const sameColumn = sourceColumn === targetColumn;
        let side = Math.sign(link.target.x - link.source.x);
        if (!side) {
            side = sourceColumn < this._columns.length - 1 ? 1 : -1;
        }
        const sourceBoundary = {
            x: link.source.x
                + side * (link.source.__view?.width || 108) / 2,
            y: link.source.y + (Number(link.__sourcePortOffset) || 0),
        };
        const targetBoundary = {
            x: link.target.x
                + (sameColumn ? side : -side)
                * (link.target.__view?.width || 108) / 2,
            y: link.target.y + (Number(link.__targetPortOffset) || 0),
        };
        const dx = targetBoundary.x - sourceBoundary.x;
        const dy = targetBoundary.y - sourceBoundary.y;
        const horizontal = Math.abs(dx) >= Math.abs(dy);
        const sign = Number(link.__curveSign) || 1;
        const initialMagnitude = Math.max(
            4,
            Number(link.__curveMagnitude) || 5,
        );
        const magnitudes = [initialMagnitude];
        for (const magnitude of [14, 22, 32, 44, 58, 76, 96, 120, 148, 180]) {
            if (magnitude > initialMagnitude) magnitudes.push(magnitude);
        }

        const candidates = [];
        magnitudes.forEach((magnitude, index) => {
            const signOrder = index % 2 === 0 ? [sign, -sign] : [-sign, sign];
            signOrder.forEach((direction) => {
                candidates.push([direction * magnitude, direction * magnitude]);
                candidates.push([direction * magnitude, -direction * magnitude]);
                candidates.push([-direction * magnitude, direction * magnitude]);
            });
        });

        let fallback = null;
        for (const [firstOffset, secondOffset] of candidates) {
            const control1 = horizontal
                ? {
                    x: sourceBoundary.x + dx * 0.42,
                    y: sourceBoundary.y + firstOffset,
                }
                : {
                    x: sourceBoundary.x + firstOffset,
                    y: sourceBoundary.y + dy * 0.42,
                };
            const control2 = horizontal
                ? {
                    x: targetBoundary.x - dx * 0.42,
                    y: targetBoundary.y + secondOffset,
                }
                : {
                    x: targetBoundary.x + secondOffset,
                    y: targetBoundary.y - dy * 0.42,
                };
            const samples = this._sampleCubic(
                sourceBoundary,
                control1,
                control2,
                targetBoundary,
            );
            const curve = {
                control1,
                control2,
                sourceBoundary,
                targetBoundary,
                samples,
                labelPoint: samples[Math.floor(samples.length / 2)],
            };
            if (!fallback) fallback = curve;
            if (this._curveHitsNode(link, samples)) continue;
            if (occupiedCurves.some(existing => (
                this._curvesOverlap(samples, existing)
            ))) continue;
            return {
                ...curve,
                path: `M${sourceBoundary.x.toFixed(1)},${sourceBoundary.y.toFixed(1)} `
                    + `C${control1.x.toFixed(1)},${control1.y.toFixed(1)} `
                    + `${control2.x.toFixed(1)},${control2.y.toFixed(1)} `
                    + `${targetBoundary.x.toFixed(1)},${targetBoundary.y.toFixed(1)}`,
            };
        }

        return {
            ...fallback,
            path: `M${fallback.sourceBoundary.x.toFixed(1)},${fallback.sourceBoundary.y.toFixed(1)} `
                + `C${fallback.control1.x.toFixed(1)},${fallback.control1.y.toFixed(1)} `
                + `${fallback.control2.x.toFixed(1)},${fallback.control2.y.toFixed(1)} `
                + `${fallback.targetBoundary.x.toFixed(1)},${fallback.targetBoundary.y.toFixed(1)}`,
        };
    },

    /**
     * 返回根据节点避障和边分散要求预先计算好的平滑曲线。
     */
    _linkPath(link) {
        return link && link.__curvePath ? link.__curvePath : '';
    },

    /**
     * 统一刷新节点与边的位置。
     */
    _tick(linkSelection, nodeSelection) {
        nodeSelection.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);

        linkSelection.select('.link')
            .attr('d', d => this._linkPath(d));

        linkSelection.select('.link-label')
            .attr('x', d => (d.__labelPoint ? d.__labelPoint.x : 0))
            .attr('y', d => (d.__labelPoint ? d.__labelPoint.y : 0));

        linkSelection.select('.link-app-hop')
            .attr('cx', d => (d.__labelPoint ? d.__labelPoint.x : 0))
            .attr('cy', d => (d.__labelPoint ? d.__labelPoint.y : -10));
    },

    /**
     * 根据卡片信息刷新节点 DOM。
     */
    _updateNodeCard(selection, d) {
        const view = d.__view || { width: 96, height: 46, title: d.id, subtitle: '', typeName: d.type, color: '#6e7b8a' };
        const left = -view.width / 2;
        const top = -view.height / 2;

        selection.select('.node-card')
            .attr('x', left)
            .attr('y', top)
            .attr('width', view.width)
            .attr('height', view.height)
            .attr('rx', 6);

        selection.select('.node-accent')
            .attr('x', left)
            .attr('y', top)
            .attr('width', 3)
            .attr('height', view.height)
            .attr('rx', 2)
            .attr('fill', view.appColor || view.color);

        selection.select('.node-type')
            .attr('x', left + 12)
            .attr('y', top + 15)
            .attr('fill', view.color)
            .text(view.typeText || view.typeName);

        selection.select('.node-title')
            .attr('x', left + 12)
            .attr('y', top + 31)
            .text(view.title);

        selection.select('.node-subtitle')
            .attr('x', left + 12)
            .attr('y', top + 43)
            .text(view.subtitle || '');

        selection.select('.node-app')
            .attr('x', left + view.width - 10)
            .attr('y', top + 15)
            .attr('text-anchor', 'end')
            .attr('fill', view.appColor || '#6e7b8a')
            .text(view.appText || '');

        selection.select('title')
            .text(`${view.typeName}${view.appText ? ` · ${view.appText}` : ''}${view.module ? ` · 模块 ${view.module}` : ''} · ${view.full}`);
    },

    /**
     * 绘制列标题与迭代行背景，让结构更易读。
     */
    _renderStageGuides() {
        const layer = this.g.selectAll('.stage-layer').data([null]);
        const layerEnter = layer.enter()
            .insert('g', ':first-child')
            .attr('class', 'stage-layer');
        const stage = layerEnter.merge(layer);

        const columns = this._columns || [];
        const colLabels = stage.selectAll('.stage-col-label').data(columns, d => d.key);
        colLabels.exit().remove();
        colLabels.enter()
            .append('text')
            .attr('class', 'stage-col-label')
            .merge(colLabels)
            .attr('x', d => d.x)
            .attr('y', 20)
            .attr('text-anchor', 'middle')
            .text(d => d.label);

        const rows = this._rows || [];
        const bands = stage.selectAll('.stage-row-band').data(rows, d => d.idx);
        bands.exit().remove();
        bands.enter()
            .append('rect')
            .attr('class', 'stage-row-band')
            .merge(bands)
            .attr('class', d => `stage-row-band${d.idx % 2 === 1 ? ' alt' : ''}`)
            .attr('x', d => d.left)
            .attr('y', d => d.top)
            .attr('width', d => d.width)
            .attr('height', d => d.height)
            .attr('rx', 6);

        const rowLabels = stage.selectAll('.stage-row-label').data(rows, d => d.idx);
        rowLabels.exit().remove();
        rowLabels.enter()
            .append('text')
            .attr('class', 'stage-row-label')
            .merge(rowLabels)
            .attr('x', d => d.left - 10)
            .attr('y', d => d.y + 3)
            .attr('text-anchor', 'end')
            .text(d => `R${d.idx + 1}`);
    },

    /**
     * 按执行顺序渲染 APP 调用流程条。
     * 行顺序来自结构化布局，因此时间维度不会被 APP 分组打乱。
     */
    _renderAppFlow() {
        const container = document.getElementById('appFlow');
        if (!container) return;

        const segments = [];

        (this._rows || []).forEach((row) => {
            const tool = row.tool;
            const app = tool ? this._canonicalApp(tool) : '';
            if (!app || app === 'system') return;

            const last = segments[segments.length - 1];
            if (last && last.app === app) {
                last.count += 1;
            } else {
                segments.push({ app, count: 1 });
            }
        });

        if (segments.length === 0) {
            container.hidden = true;
            container.innerHTML = '';
            return;
        }

        container.hidden = false;
        container.innerHTML = '';

        const title = document.createElement('span');
        title.className = 'app-flow-title';
        title.textContent = 'APP 调用顺序';
        container.appendChild(title);

        segments.forEach((segment, index) => {
            if (index > 0) {
                const arrow = document.createElement('span');
                arrow.className = 'app-flow-arrow app-flow-cross-app';
                arrow.setAttribute('aria-hidden', 'true');
                arrow.title = '跨 APP 数据或控制依赖';
                arrow.textContent = '→';
                container.appendChild(arrow);
            }

            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'app-flow-chip';
            chip.dataset.app = segment.app;
            chip.setAttribute('aria-pressed', 'false');
            chip.title = `点击聚焦 ${segment.app} 的节点与关联边`;
            chip.style.setProperty('--app-color', this._appColor(segment.app));

            const dot = document.createElement('span');
            dot.className = 'app-flow-dot';

            const name = document.createElement('span');
            name.className = 'app-flow-name';
            name.textContent = this._appLabel(segment.app);

            const count = document.createElement('span');
            count.className = 'app-flow-count';
            count.textContent = `×${segment.count}`;

            chip.append(dot, name, count);
            chip.addEventListener('click', () => {
                if (chip.getAttribute('aria-pressed') === 'true') {
                    this.clearHighlight();
                } else {
                    this._focusApp(segment.app);
                }
            });

            container.appendChild(chip);
        });

        const handoffs = segments.length - 1;
        if (handoffs > 0) {
            const summary = document.createElement('span');
            summary.className = 'app-flow-summary';
            summary.textContent = `跨 APP 切换 ${handoffs} 次`;
            container.appendChild(summary);
        }
    },

    /**
     * 悬停节点：聚焦关联节点与边，弱化其余元素。
     */
    _focusNode(node) {
        const relatedNodes = new Set([node.id]);

        this.links.forEach((link) => {
            const sourceId = link.source ? (link.source.id || link.source) : null;
            const targetId = link.target ? (link.target.id || link.target) : null;
            if (sourceId === node.id || targetId === node.id) {
                relatedNodes.add(sourceId);
                relatedNodes.add(targetId);
            }
        });

        this.g.selectAll('.node')
            .classed('dimmed', n => !relatedNodes.has(n.id))
            .classed('focused', n => n.id === node.id);

        this.g.selectAll('.link-group')
            .classed('dimmed', l => {
                const sourceId = String(l.source?.id || l.source || '');
                const targetId = String(l.target?.id || l.target || '');
                return sourceId !== String(node.id) && targetId !== String(node.id);
            })
            .classed('highlighted', l => {
                const sourceId = String(l.source?.id || l.source || '');
                const targetId = String(l.target?.id || l.target || '');
                return sourceId === String(node.id) || targetId === String(node.id);
            })
            .classed('bundle-expanded', l => (
                Boolean(l.__bundleHidden || l.__contextHidden)
                && (
                    String(l.source.id || l.source) === String(node.id)
                    || String(l.target.id || l.target) === String(node.id)
                )
            ));
    },

    /**
     * 悬停边：只聚焦这条边及其两端节点。
     */
    _focusLink(link) {
        const sourceId = link.source ? (link.source.id || link.source) : null;
        const targetId = link.target ? (link.target.id || link.target) : null;

        this.g.selectAll('.link-group')
            .classed('dimmed', l => l !== link)
            .classed('highlighted', l => l === link)
            .classed('bundle-expanded', l => (
                Boolean(link.__bundleGroup)
                && l.__bundleGroup === link.__bundleGroup
            ));

        this.g.selectAll('.node')
            .classed('dimmed', n => n.id !== sourceId && n.id !== targetId)
            .classed('focused', n => n.id === sourceId || n.id === targetId);
    },

    /**
     * 渲染拓扑图（结构化布局，增量更新模式）
     */
    render() {
        const self = this;
        const filtered = this._filteredGraphData();
        const nodes = filtered.nodes;
        const graphLinks = filtered.links;
        const visibleNodeIds = new Set(nodes.map((node) => node.id));
        this._renderedNodes = nodes;

        // 1. 生成节点卡片信息并计算结构化布局
        this._prepareNodeViews(nodes, graphLinks);
        this._computeStructuredLayout(nodes, graphLinks);

        // 2. 绘制列标题与迭代行背景
        this._renderStageGuides();
        this._renderAppFlow();
        if (typeof AUDIT_SUMMARY !== 'undefined') {
            AUDIT_SUMMARY.render(this);
        }

        // 3. 过滤行间连线
        const links = this._visibleLinks(graphLinks, visibleNodeIds);
        this._renderedLinks = links;
        this._renderLinks = links;
        this._prepareLinkRoutes(nodes, links);

        this.simulation.nodes(nodes).force('link').links(links);

        // --- 增量更新边 ---
        const linkGroup = this.g.selectAll('.link-group')
            .data(links, d => `${d.source.id || d.source}→${d.target.id || d.target}:${d.relation}`);

        linkGroup.exit()
            .transition()
            .duration(200)
            .style('opacity', 0)
            .remove();

        const linkEnter = linkGroup.enter()
            .append('g')
            .attr('class', d => this._linkGroupClass(d))
            .style('opacity', 0);

        linkEnter.append('path')
            .attr('class', 'link')
            .attr('stroke', d => (this._relationClass(d.relation) === 'belongs-to'
                ? '#6e7b8a'
                : (self.config.linkColors[d.relation] || '#5a6a7a')));

        linkEnter.append('text')
            .attr('class', 'link-label')
            .attr('text-anchor', 'middle')
            .attr('dy', -7)
            .text(d => this._linkLabelText(d));

        linkEnter.append('circle')
            .attr('class', 'link-app-hop')
            .attr('r', 3.5);

        const link = linkEnter.merge(linkGroup);
        link.attr('class', d => this._linkGroupClass(d));
        link.select('.link').attr('marker-end', d => this._linkMarker(d));
        link.select('.link-label').text(d => this._linkLabelText(d));
        link.select('.link-app-hop').attr('fill', d => this._appColor(d.target && d.target.app));

        linkEnter.transition()
            .duration(300)
            .style('opacity', 1);

        // --- 增量更新节点 ---
        const node = this.g.selectAll('.node')
            .data(nodes, d => d.id);

        node.exit()
            .transition()
            .duration(200)
            .style('opacity', 0)
            .remove();

        const nodeEnter = node.enter()
            .append('g')
            .attr('class', d => this._nodeClass(d))
            .style('opacity', 0)
            .call(d3.drag()
                .on('start', (event, d) => {
                    if (!event.active) self.simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on('drag', (event, d) => {
                    d.fx = event.x;
                    d.fy = event.y;
                })
                .on('end', (event, d) => {
                    if (!event.active) self.simulation.alphaTarget(0);
                    d.fx = d.x;
                    d.fy = d.y;
                    self._prepareLinkRoutes(
                        self._renderedNodes || self.nodes,
                        self._renderedLinks || self.links,
                    );
                    self.simulation.alpha(0.1).restart();
                })
            );

        nodeEnter.append('title');
        nodeEnter.append('rect').attr('class', 'node-card');
        nodeEnter.append('rect').attr('class', 'node-accent');
        nodeEnter.append('text').attr('class', 'node-type');
        nodeEnter.append('text').attr('class', 'node-app');
        nodeEnter.append('text').attr('class', 'node-title');
        nodeEnter.append('text').attr('class', 'node-subtitle');

        const nodeMerged = nodeEnter.merge(node);

        nodeMerged.attr('class', d => this._nodeClass(d));
        nodeMerged.each(function (d) {
            self._updateNodeCard(d3.select(this), d);
        });

        nodeEnter.transition()
            .duration(300)
            .style('opacity', 1);

        // --- 交互事件 ---
        nodeMerged.on('mouseenter', function(event, d) {
            self._focusNode(d);
        });

        nodeMerged.on('mouseleave', function() {
            self.clearHighlight();
        });

        nodeMerged.on('click', function(event, d) {
            self.showNodeDetail(d);
        });

        nodeMerged
            .attr('role', d => (
                d.type === 'HumanAuthorization'
                    && String(d.status || 'pending').toLowerCase() === 'pending'
                    ? 'button'
                    : null
            ))
            .attr('tabindex', d => (
                d.type === 'HumanAuthorization'
                    && String(d.status || 'pending').toLowerCase() === 'pending'
                    ? '0'
                    : null
            ))
            .attr('aria-label', d => (
                d.type === 'HumanAuthorization'
                    ? `人工授权：${this._authorizationStatusLabel(d.status)}，点击查看详情`
                    : null
            ))
            .on('keydown', function(event, d) {
                if (
                    (event.key === 'Enter' || event.key === ' ')
                    && d.type === 'HumanAuthorization'
                ) {
                    event.preventDefault();
                    self.showNodeDetail(d);
                }
            });

        link.on('mouseenter', function(event, d) {
            self._focusLink(d);
        });

        link.on('mouseleave', function() {
            self.clearHighlight();
        });

        // --- 位置刷新（布局固定，tick 用于拖拽与曲线重算） ---
        this.simulation.on('tick', null);
        this.simulation.on('tick', () => {
            self._tick(link, nodeMerged);
        });

        this._tick(link, nodeMerged);

        // 新增风险、FSM 和出口节点可能使内容高度超过可视区域。
        // 仅在布局确实溢出时自动适配一次，避免普通刷新打断用户缩放。
        if (this._layoutNeedsFit) {
            requestAnimationFrame(() => this.resetView());
        }
    },

    /**
     * 计算结构化布局
     * Prompt 节点在左、AIAgent 在中间、右侧从上到下每一行 = 一次思考 → 工具调用 → 结果
     */
    _computeStructuredLayout(nodes = this.nodes, links = this.links) {
        const w = this.config.width || 1200;
        const h = this.config.height || 800;

        const isType = (n, t) => n && n.type === t;

        const prompts = nodes.filter(n => isType(n, 'Prompt'));
        const agents = nodes.filter(n => isType(n, 'AIAgent'));
        const thoughts = nodes.filter(n => isType(n, 'AIModelInvocation'));
        const tools = nodes.filter(n => isType(n, 'AgentTool'));
        const dataNodes = nodes.filter(n => isType(n, 'DomainData'));
        const auxiliaryNodes = nodes.filter(n => isType(n, 'RiskEvent') || isType(n, 'PolicyEvent') || isType(n, 'TaskState') || isType(n, 'EgressSink') || isType(n, 'HumanAuthorization'));
        nodes.forEach((node) => {
            node.fx = null;
            node.fy = null;
        });
        // 图谱节点按捕获顺序排列，可用于恢复工具的真实执行顺序
        const nodeOrder = new Map(nodes.map((node, index) => [node.id, index]));

        const relatedAuxiliary = (nodeId) => {
            const risks = links
                .filter(l => l.source && l.target && l.target.id === nodeId && (l.relation === 'risk_of' || l.relation === 'policy_of') && (isType(l.source, 'RiskEvent') || isType(l.source, 'PolicyEvent')))
                .map(l => l.source);
            const states = links
                .filter(l => l.source && l.target && l.source.id === nodeId && l.relation === 'transition_to' && isType(l.target, 'TaskState'))
                .map(l => l.target);
            const sinks = links
                .filter(l => l.source && l.target && l.source.id === nodeId && l.relation === 'egress_to' && isType(l.target, 'EgressSink'))
                .map(l => l.target);
            const authorizations = links
                .filter(l => l.source && l.target && l.target.id === nodeId && l.relation === 'authorizes' && isType(l.source, 'HumanAuthorization'))
                .map(l => l.source);
            return [...new Set([...risks, ...states, ...sinks, ...authorizations])];
        };

        // 收集工具对应的数据节点（输入 used / 输出 produces）
        const rowResultsFor = (tool) => {
            const outputs = links
                .filter(l => l.source && l.target && l.source.id === tool.id && l.relation === 'produces' && isType(l.target, 'DomainData'))
                .map(l => l.target);
            const inputs = links
                .filter(l => l.source && l.target && l.source.id === tool.id && l.relation === 'used' && isType(l.target, 'DomainData'))
                .map(l => l.target);
            return {
                inputs: [...new Set(inputs)],
                outputs: [...new Set(outputs)],
                auxiliary: relatedAuxiliary(tool.id),
            };
        };

        // 构建迭代行：思考 → 工具 → 结果
        const rows = [];
        const usedTools = new Set();

        for (const thought of thoughts) {
            // 思考直接通知的工具
            const directTools = links
                .filter(l => l.source && l.target && l.source.id === thought.id && l.relation === 'informed' && isType(l.target, 'AgentTool'))
                .map(l => l.target);
            // 有输入数据时：思考 → informed → 输入数据，工具 → used → 输入数据
            const viaDataTools = links
                .filter(l => l.source && l.target && l.source.id === thought.id && l.relation === 'informed' && isType(l.target, 'DomainData'))
                .map(l => l.target)
                .flatMap(dataNode =>
                    links
                        .filter(l => l.source && l.target && l.target.id === dataNode.id && l.relation === 'used' && isType(l.source, 'AgentTool'))
                        .map(l => l.source)
                );
            const rowTools = [...new Set([...directTools, ...viaDataTools])]
                .sort((a, b) => (nodeOrder.get(a.id) ?? 0) - (nodeOrder.get(b.id) ?? 0));
            if (rowTools.length === 0) {
                rows.push({
                    thought,
                    tool: null,
                    inputs: [],
                    outputs: [],
                    auxiliary: relatedAuxiliary(thought.id),
                });
            } else {
                rowTools.forEach((tool, toolIndex) => {
                    usedTools.add(tool.id);
                    const results = rowResultsFor(tool);
                    rows.push({
                        thought,
                        tool,
                        inputs: results.inputs,
                        outputs: results.outputs,
                        auxiliary: [
                            ...new Set([
                                ...(toolIndex === 0 ? relatedAuxiliary(thought.id) : []),
                                ...results.auxiliary,
                            ]),
                        ],
                    });
                });
            }
        }

        // 没有关联思考的工具 → 单独成行
        for (const tool of tools) {
            if (usedTools.has(tool.id)) continue;
            const results = rowResultsFor(tool);
            rows.push({
                thought: null,
                tool,
                inputs: results.inputs,
                outputs: results.outputs,
                auxiliary: results.auxiliary,
            });
        }

        // 兜底：没有任何行的数据节点
        const usedData = new Set();
        rows.forEach(r => {
            r.inputs.forEach(d => usedData.add(d.id));
            r.outputs.forEach(d => usedData.add(d.id));
            r.auxiliary.forEach(d => usedData.add(d.id));
        });
        const leftoverData = [...dataNodes, ...auxiliaryNodes].filter(d => !usedData.has(d.id));
        if (rows.length === 0 && leftoverData.length > 0) {
            rows.push({
                thought: null,
                tool: null,
                inputs: leftoverData.filter(d => isType(d, 'DomainData')),
                outputs: [],
                auxiliary: leftoverData.filter(d => !isType(d, 'DomainData')),
            });
        }

        const inputDataNodes = [...new Set(rows.flatMap(row => row.inputs))];
        const outputDataNodes = [...new Set(rows.flatMap(row => row.outputs))];
        const widthOfNodes = (list) => Math.max(
            108,
            ...list.map(node => Number(node.__view?.width) || 108),
        );
        const columnWidths = [
            widthOfNodes(prompts),
            widthOfNodes(agents),
            widthOfNodes(thoughts),
            widthOfNodes(inputDataNodes),
            widthOfNodes(tools),
            widthOfNodes(outputDataNodes),
            widthOfNodes(auxiliaryNodes),
        ];
        const baseGap = Math.max(156, Math.min(200, w * 0.13));
        const minimumLayoutWidth = columnWidths.reduce(
            (sum, value) => sum + value,
            0,
        ) + baseGap * 6;
        const horizontalGap = minimumLayoutWidth < w
            ? Math.min(
                220,
                Math.max(baseGap, (w - 48 - columnWidths.reduce(
                    (sum, value) => sum + value,
                    0,
                )) / 6),
            )
            : baseGap;
        const layoutWidth = columnWidths.reduce(
            (sum, value) => sum + value,
            0,
        ) + horizontalGap * 6;
        let cursorX = layoutWidth < w
            ? (w - layoutWidth) / 2
            : 24;
        const columnCenters = columnWidths.map(width => {
            const center = cursorX + width / 2;
            cursorX += width + horizontalGap;
            return center;
        });
        const [
            colPrompt,
            colAgent,
            colThought,
            colInput,
            colTool,
            colOutput,
            colAuxiliary,
        ] = columnCenters;
        this._layoutWidth = layoutWidth;

        this._columns = [
            { key: 'prompt', x: colPrompt, label: '提示词' },
            { key: 'agent', x: colAgent, label: '智能体' },
            { key: 'thought', x: colThought, label: '推理' },
            { key: 'input', x: colInput, label: '输入数据' },
            { key: 'tool', x: colTool, label: '工具调用' },
            { key: 'output', x: colOutput, label: '输出数据' },
            { key: 'auxiliary', x: colAuxiliary, label: '风险 / FSM 状态' },
        ];

        // Reserve room for column headers plus the upper half of a multi-node
        // stack. Otherwise the first output/risk row can overlap "输出数据".
        const topMargin = 132;
        const bottomMargin = 24;
        const rowCount = Math.max(1, rows.length);
        const usableHeight = Math.max(160, h - topMargin - bottomMargin);
        const stackNeed = Math.max(
            1,
            ...rows.map(row => Math.max(
                row.inputs.length,
                row.outputs.length,
                row.auxiliary.length,
                1
            ))
        );
        const nodeVerticalStep = 68;
        const minRowGap = stackNeed * nodeVerticalStep + 26;
        const rowGap = Math.max(
            minRowGap,
            Math.min(220, Math.max(96, usableHeight / rowCount)),
        );
        const contentHeight = topMargin + bottomMargin + rowGap * Math.max(0, rowCount - 1);
        this._layoutNeedsFit = (
            contentHeight > h + 1
            || layoutWidth > w + 1
        );
        const layoutHeight = Math.max(h, contentHeight);
        const layoutUsableHeight = Math.max(160, layoutHeight - topMargin - bottomMargin);
        const rowStart = topMargin + Math.max(0, (layoutUsableHeight - rowGap * (rowCount - 1)) / 2);
        const centerY = topMargin + layoutUsableHeight / 2;

        // 行背景与行号的几何信息
        const bandLeft = colThought - columnWidths[2] / 2 - 18;
        const bandRight = colAuxiliary + columnWidths[6] / 2 + 18;
        this._rows = rows.map((row, idx) => ({
            idx,
            thought: row.thought,
            tool: row.tool,
            inputs: row.inputs,
            outputs: row.outputs,
            auxiliary: row.auxiliary,
            y: rowStart + idx * rowGap,
            left: bandLeft,
            top: rowStart + idx * rowGap - rowGap / 2 + 5,
            width: Math.max(140, bandRight - bandLeft),
            height: Math.max(40, rowGap - 10),
        }));

        // 行号映射（首次认领，避免同一节点被多个行覆盖归属）
        this._nodeRow = new Map();
        const mark = (n, idx) => { if (n && !this._nodeRow.has(n.id)) this._nodeRow.set(n.id, idx); };

        rows.forEach((row, idx) => {
            mark(row.thought, idx);
            mark(row.tool, idx);
            row.inputs.forEach(d => mark(d, idx));
            row.outputs.forEach(d => mark(d, idx));
            row.auxiliary.forEach(d => mark(d, idx));
        });

        // Prompt 节点：左列
        prompts.forEach((p, i) => {
            const y = prompts.length === 1 ? centerY : rowStart + i * ((h * 0.7) / Math.max(1, prompts.length - 1));
            p.x = colPrompt; p.y = y;
            p.fx = colPrompt; p.fy = y;
        });

        // AIAgent 节点：中间
        agents.forEach((a, i) => {
            const y = agents.length === 1 ? centerY : rowStart + i * rowGap;
            a.x = colAgent; a.y = y;
            a.fx = colAgent; a.fy = y;
        });

        // 行内布局：按节点所属行定位（跨行数据留在首次认领它的行）
        rows.forEach((row, idx) => {
            const y = rowStart + idx * rowGap;
            if (row.thought && this._nodeRow.get(row.thought.id) === idx) {
                row.thought.x = colThought; row.thought.y = y;
                row.thought.fx = colThought; row.thought.fy = y;
            }
            if (row.tool && this._nodeRow.get(row.tool.id) === idx) {
                row.tool.x = colTool; row.tool.y = y;
                row.tool.fx = colTool; row.tool.fy = y;
            }

            const placeColumn = (list, x) => {
                const claimed = list.filter(d => d && this._nodeRow.get(d.id) === idx);
                claimed.forEach((d, k) => {
                    const offset = claimed.length === 1 ? 0 : (k - (claimed.length - 1) / 2) * nodeVerticalStep;
                    d.x = x; d.y = y + offset;
                    d.fx = x; d.fy = y + offset;
                });
            };
            placeColumn(row.inputs, colInput);
            placeColumn(row.outputs, colOutput);
            placeColumn(row.auxiliary, colAuxiliary);
        });

        // 兜底：未被布局的节点按列放到现有节点之后，避免落在行节点上方。
        const assigned = new Set(nodes.filter(n => n.fx != null).map(n => n.id));
        const unassigned = nodes.filter(n => !assigned.has(n.id));
        const unassignedIds = new Set(unassigned.map(node => node.id));
        const unassignedGroups = new Map();
        unassigned.forEach((node) => {
            const x = isType(node, 'RiskEvent') || isType(node, 'PolicyEvent') || isType(node, 'TaskState') || isType(node, 'EgressSink') || isType(node, 'HumanAuthorization')
                ? colAuxiliary
                : colThought;
            if (!unassignedGroups.has(x)) unassignedGroups.set(x, []);
            unassignedGroups.get(x).push(node);
        });
        unassignedGroups.forEach((group, x) => {
            const occupied = nodes.filter(node =>
                !unassignedIds.has(node.id)
                && node.fx === x
            );
            let nextTop = occupied.length
                ? Math.max(...occupied.map(node => (
                    node.y + (node.__view?.height || 46) / 2
                ))) + 22
                : centerY - 23;
            group
                .sort((a, b) => (
                    (nodeOrder.get(a.id) ?? 0) - (nodeOrder.get(b.id) ?? 0)
                ))
                .forEach((node) => {
                    const height = node.__view?.height || 46;
                    const y = nextTop + height / 2;
                    node.x = x; node.y = y;
                    node.fx = x; node.fy = y;
                    nextTop = y + height / 2 + 22;
                });
        });

        nodes.forEach((node) => {
            let bestIndex = 0;
            let bestDistance = Infinity;
            this._columns.forEach((column, index) => {
                const distance = Math.abs(node.x - column.x);
                if (distance < bestDistance) {
                    bestDistance = distance;
                    bestIndex = index;
                }
            });
            node.__columnIndex = bestIndex;
        });

        const maxNodeBottom = Math.max(
            ...nodes.map(node => (
                node.y + (node.__view?.height || 46) / 2
            )),
        );
        this._layoutNeedsFit = this._layoutNeedsFit || maxNodeBottom > h - bottomMargin;
    },

    /**
     * 过滤连线：默认仅展示主因果链，审计模式再展开状态与证据边。
     */
    _visibleLinks(baseLinks = this.links, nodeIds = null) {
        const alwaysHiddenRelations = new Set([
            'informed',
            'belongsTo',
            'wasAssociatedWith',
            'wasAttributedTo',
            'wasInformedBy',
            'wasGeneratedBy',
            'stateTransition',
            'transition_from',
            'hasState',
            'contains',
        ]);
        const primaryRelations = new Set(this.config.primaryLinkRelations);
        const showAuditEdges = this.config.linkMode === 'audit';
        const filtered = baseLinks.filter(l => {
            const sourceType = l.source && l.source.type;
            const targetType = l.target && l.target.type;
            const sourceId = l.source && typeof l.source === 'object'
                ? l.source.id
                : l.source;
            const targetId = l.target && typeof l.target === 'object'
                ? l.target.id
                : l.target;
            if (nodeIds && (!nodeIds.has(sourceId) || !nodeIds.has(targetId))) {
                return false;
            }

            // Membership and reverse PROV aliases duplicate the canonical edge.
            if (alwaysHiddenRelations.has(l.relation)) {
                return false;
            }
            if (!showAuditEdges && !primaryRelations.has(l.relation)) {
                return false;
            }

            // Prompt -> invocation is the canonical rendering. The reverse
            // invocation -> prompt "used" edge creates a crossing back-arrow.
            if (
                l.relation === 'used'
                && sourceType === 'AIModelInvocation'
                && targetType === 'Prompt'
            ) {
                return false;
            }

            return true;
        });
        return this._finalizeDisplayLinks(filtered);
    },

    _finalizeDisplayLinks(links) {
        const evidenceGroups = new Map();
        const remaining = [];
        links.forEach((link) => {
            if (link.relation !== 'risk_evidence' && link.relation !== 'source_of') {
                remaining.push(link);
                return;
            }
            const sourceId = link.source.id || link.source;
            const targetId = link.target.id || link.target;
            const key = `${sourceId}\u0000${targetId}`;
            if (!evidenceGroups.has(key)) evidenceGroups.set(key, []);
            evidenceGroups.get(key).push(link);
        });
        evidenceGroups.forEach((group) => {
            if (group.length === 1) {
                remaining.push(group[0]);
                return;
            }
            const representative = group.find(link => link.relation === 'risk_evidence')
                || group[0];
            remaining.push({
                ...representative,
                __displayRelations: [...new Set(group.map(link => link.relation))],
            });
        });
        return this._annotateLinkBundles(remaining);
    },

    _annotateLinkBundles(links) {
        const groups = new Map();
        const register = (key, link) => {
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(link);
        };
        links.forEach((link) => {
            if (link.relation === 'produces') {
                register(`produces:${link.source.id}`, link);
            } else if (
                link.relation === 'informed'
                && link.source.type === 'Prompt'
            ) {
                register(`context:${link.source.id}`, link);
            } else if (link.relation === 'wasDerivedFrom') {
                register(`derived:${link.target.id}`, link);
            }
        });

        const bundled = new Map();
        groups.forEach((group, key) => {
            if (group.length < 2) return;
            const ordered = group.slice().sort((first, second) => {
                const firstOther = key.startsWith('derived:')
                    ? first.source
                    : first.target;
                const secondOther = key.startsWith('derived:')
                    ? second.source
                    : second.target;
                return (Number(firstOther.y) || 0) - (Number(secondOther.y) || 0)
                    || String(firstOther.id).localeCompare(String(secondOther.id));
            });
            const primaryIndex = Math.floor((ordered.length - 1) / 2);
            ordered.forEach((link, index) => {
                bundled.set(link, {
                    ...link,
                    __bundleGroup: key,
                    __bundleCount: ordered.length,
                    __bundleHidden: index !== primaryIndex,
                    __bundlePrimary: index === primaryIndex,
                });
            });
        });
        const hiddenContextRelations = new Set([
            'risk_of',
            'policy_of',
            'authorizes',
        ]);
        return links.map((link) => {
            const displayLink = bundled.get(link) || link;
            return hiddenContextRelations.has(displayLink.relation)
                ? { ...displayLink, __contextHidden: true }
                : displayLink;
        });
    },

    /**
     * 高亮节点的关联路径
     */
    highlightPath(d) {
        this._focusNode(d);
    },

    focusConfirmationEvidence(request) {
        if (!request || !Array.isArray(this.nodes) || !this.nodes.length) {
            return;
        }
        const requestId = String(request.request_id || '');
        const toolName = String(request.tool_name || '');
        const flow = request.flow_check || {};
        const fieldSources = Array.isArray(flow.field_sources)
            ? flow.field_sources
            : [];
        const evidenceActivityIds = new Set(
            fieldSources
                .map(item => String(item.source_activity_id || ''))
                .filter(Boolean),
        );
        const evidenceEntityIds = new Set(
            fieldSources
                .map(item => String(item.source_entity_id || ''))
                .filter(Boolean),
        );
        const sourceActions = new Set(
            fieldSources
                .map(item => String(item.source_action || ''))
                .filter(Boolean),
        );
        const authorization = this.nodes.find(node =>
            node.type === 'HumanAuthorization'
            && String(node.request_id || '') === requestId
        );
        const toolActivity = this.nodes.find(node =>
            node.type === 'AgentTool'
            && String(node?.l2_confirmation?.request_id || '') === requestId
        ) || [...this.nodes].reverse().find(node =>
            node.type === 'AgentTool'
            && (
                String(node.tool_base_name || '') === toolName
                || String(node.tool_name || '') === toolName
                || String(node.label || '') === toolName
            )
        );
        const seeds = new Set();
        [authorization, toolActivity].forEach(node => {
            if (node?.id) seeds.add(String(node.id));
        });
        this.nodes.forEach(node => {
            const nodeId = String(node.id || '');
            if (
                evidenceActivityIds.has(nodeId)
                || (
                    node.type === 'DomainData'
                    && (
                        evidenceEntityIds.has(String(node.entity_id || ''))
                        || sourceActions.has(String(node.source_action || ''))
                    )
                )
            ) {
                seeds.add(nodeId);
            }
        });
        if (!seeds.size) {
            if (toolActivity) this._focusNode(toolActivity);
            return;
        }

        const related = new Set(seeds);
        let frontier = new Set(seeds);
        for (let hop = 0; hop < 2; hop += 1) {
            const next = new Set();
            this.links.forEach(link => {
                const sourceId = String(link.source?.id || link.source || '');
                const targetId = String(link.target?.id || link.target || '');
                if (frontier.has(sourceId) && targetId) {
                    if (!related.has(targetId)) next.add(targetId);
                    related.add(targetId);
                }
                if (frontier.has(targetId) && sourceId) {
                    if (!related.has(sourceId)) next.add(sourceId);
                    related.add(sourceId);
                }
            });
            frontier = next;
            if (!frontier.size) break;
        }

        this.g.selectAll('.node')
            .classed('dimmed', node => !related.has(String(node.id)))
            .classed('focused', node => seeds.has(String(node.id)));
        this.g.selectAll('.link-group')
            .classed('dimmed', link => {
                const sourceId = String(link.source?.id || link.source || '');
                const targetId = String(link.target?.id || link.target || '');
                return !related.has(sourceId) || !related.has(targetId);
            })
            .classed('highlighted', link => {
                const sourceId = String(link.source?.id || link.source || '');
                const targetId = String(link.target?.id || link.target || '');
                return related.has(sourceId) && related.has(targetId);
            });

        const positioned = this.nodes.filter(node =>
            related.has(String(node.id))
            && Number.isFinite(Number(node.x))
            && Number.isFinite(Number(node.y))
        );
        if (!positioned.length || !this.zoomBehavior || !this.svg) return;
        const xs = positioned.map(node => Number(node.x));
        const ys = positioned.map(node => Number(node.y));
        const minX = Math.min(...xs);
        const maxX = Math.max(...xs);
        const minY = Math.min(...ys);
        const maxY = Math.max(...ys);
        const reservedWidth = Math.min(500, this.config.width * 0.46);
        const availableWidth = Math.max(320, this.config.width - reservedWidth);
        const scale = Math.max(
            0.18,
            Math.min(
                1.25,
                (availableWidth - 70) / Math.max(260, maxX - minX + 180),
                (this.config.height - 80) / Math.max(200, maxY - minY + 130),
            ),
        );
        const centerX = (minX + maxX) / 2;
        const centerY = (minY + maxY) / 2;
        this.svg.transition()
            .duration(450)
            .call(
                this.zoomBehavior.transform,
                d3.zoomIdentity
                    .translate(
                        availableWidth / 2 - centerX * scale,
                        this.config.height / 2 - centerY * scale,
                    )
                    .scale(scale),
            );
    },

    /**
     * 清除高亮
     */
    clearHighlight() {
        this.g.selectAll('.node')
            .classed('dimmed', false)
            .classed('focused', false);
        this.g.selectAll('.link-group')
            .classed('dimmed', false)
            .classed('highlighted', false)
            .classed('bundle-expanded', false);
        document.querySelectorAll('.app-flow-chip').forEach((chip) => {
            chip.setAttribute('aria-pressed', 'false');
        });
    },

    /**
     * 显示节点详情
     * - 区分 DomainData 的角色（输入/输出/环境变更）
     * - 显示关联边摘要
     * - 更清晰的视觉层次
     */
    showNodeDetail(d) {
        const riskLabels = window.AgentTraceRiskLabels || {};
        const panel = document.getElementById('nodeDetailPanel');
        const body = document.getElementById('nodeDetailBody');

        if (!panel || !body) return;

        const typeLabels = {
            'AIAgent': 'AI 智能体',
            'AIModelInvocation': 'LLM 推理',
            'AgentTool': '工具调用',
            'Prompt': '提示内容',
            'DomainData': '数据实体',
            'TaskState': 'FSM 状态',
            'RiskEvent': '风险事件',
            'PolicyEvent': '策略事件',
            'EgressSink': '外部出口',
            'HumanAuthorization': '人工授权',
        };

        // 角色标签映射（根据 operation 字段）
        const roleLabels = {
            'input': { label: '输入参数', color: 'var(--accent-blue)' },
            'output': { label: '输出结果', color: 'var(--accent-green)' },
            'created': { label: '环境变更 - 创建', color: 'var(--accent-orange)' },
            'updated': { label: '环境变更 - 更新', color: 'var(--accent-yellow)' },
            'deleted': { label: '环境变更 - 删除', color: 'var(--accent-red)' },
        };

        let html = `
            <div class="detail-field">
                <span class="label">类型</span>
                <div class="value">${typeLabels[d.type] || d.type}</div>
            </div>
        `;
        const displayedRiskLevel = d.type === 'AgentTool'
            ? d.tool_risk_level
            : d.risk_level;
        if (displayedRiskLevel) {
            html += `
                <div class="detail-field">
                    <span class="label">${d.type === 'AgentTool' ? '工具等级' : '风险等级'}</span>
                    <div class="value">${this._escapeHtml(displayedRiskLevel)}</div>
                </div>
            `;
        }
        if (d.l2_chain_check) {
            const chain = d.l2_chain_check;
            const checkLabels = {
                semantic_plan_relation: '任务语义关系',
                semantic_preconditions: '前置结果语义',
                semantic_destination_purpose: '接收方目的',
                semantic_effect_purpose: '操作效果目的',
                semantic_parameter_relevance: '参数语义相关性',
            };
            const failedChecks = Object.entries(chain.checks || {})
                .filter(([, passed]) => passed !== true)
                .map(([name]) => checkLabels[name] || name);
            const violations = Array.isArray(chain.violations)
                ? chain.violations
                : [];
            const manualReviewNotes = Array.isArray(chain.manual_review_notes)
                ? chain.manual_review_notes
                : [];
            html += `
                <div class="detail-field">
                    <span class="label">L2 调用链判断</span>
                    <div class="value">${this._escapeHtml(
                        chain.consistent ? '一致' : '不一致'
                    )} · ${this._escapeHtml(
                        riskLabels.hasChinese?.(chain.reason)
                            ? chain.reason
                            : (
                                chain.consistent
                                    ? '该操作与当前授权计划及前置步骤一致。'
                                    : '该操作与当前授权计划或前置步骤不一致。'
                            )
                    )}</div>
                </div>
            `;
            if (failedChecks.length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">未通过的链检查</span>
                        <div class="value">${this._escapeHtml(
                            failedChecks.join('、')
                        )}</div>
                    </div>
                `;
            }
            if (violations.length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">调用链问题</span>
                        <div class="value">${violations.map(item => {
                            const parameter = item.parameter || '未指定参数';
                            const kind = item.kind || '未分类问题';
                            const detail = item.detail || '未提供详细说明';
                            return this._escapeHtml(
                                `${parameter} · ${kind} · ${detail}`
                            );
                        }).join('<br>')}</div>
                    </div>
                `;
            }
            if (manualReviewNotes.length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">人工核对提示</span>
                        <div class="value">${manualReviewNotes.map(item => {
                            const parameter = item.parameter || '未指定参数';
                            const detail = item.explanation
                                || item.detail
                                || item.kind
                                || '自然语言内容需要人工核对';
                            return this._escapeHtml(
                                `${parameter} · ${detail}`
                            );
                        }).join('<br>')}</div>
                    </div>
                `;
            }
        }
        if (d.execution_uncertain) {
            html += `
                <div class="detail-field">
                    <span class="label">外发执行结果</span>
                    <div class="value">执行失败，结果可能不确定。为避免重复产生外部副作用，系统已禁止自动重试；需要用户明确重新发起。</div>
                </div>
            `;
        }
        if (d.l2_confirmation) {
            html += `
                <div class="detail-field">
                    <span class="label">用户确认</span>
                    <div class="value">${this._escapeHtml(
                        this._authorizationStatusLabel(
                            d.l2_confirmation.status || 'pending'
                        )
                    )}</div>
                </div>
            `;
        }
        if (d.ring3_check) {
            const flow = d.ring3_check;
            const destinationLabels = {
                fixed_authorized: '固定授权',
                derived_authorized: '受控派生',
                unauthorized: '未授权',
                not_evaluated: '未检查',
            };
            const flowSources = (d.argument_sources || [])
                .map(source => (
                    `${source.argument_root || '-'} ← `
                    + `${source.source_app || '-'}:${source.source_entity || '-'}`
                    + (source.source_risk ? ' · 来源风险' : '')
                ));
            const resolutions = (d.parameter_resolutions || [])
                .map(item => (
                    `${item.parameter || '-'}: `
                    + `${
                        riskLabels.sourceStatusLabel
                            ? riskLabels.sourceStatusLabel(item.status)
                            : item.status || '-'
                    }`
                ));
            const generationRows = Object.entries(
                flow.parameter_generation || {}
            ).map(([parameter, generation]) => {
                const confidence = Number(generation.confidence);
                const semanticSupport = (
                    generation.validation_mode === 'natural_language_manual'
                        ? '自然语言内容，仅人工核对'
                        : typeof generation.semantic_supported === 'boolean'
                        ? (
                            generation.semantic_supported
                                ? '已在来源中定位'
                                : '未直接定位，需语义核对'
                        )
                        : '语义支持未记录'
                );
                return `${parameter}: ${[
                    riskLabels.generationKindLabel
                        ? riskLabels.generationKindLabel(
                            generation.generation_kind
                        )
                        : generation.generation_kind || '未知',
                    Number.isFinite(confidence)
                        ? `${
                            generation.generation_kind === 'copy'
                                ? '控制器置信度'
                                : '模型自报置信度'
                        } ${Math.round(confidence * 100)}%`
                        : '置信度未记录',
                    semanticSupport,
                    generation.explanation || '未记录生成说明',
                ].join(' · ')}`;
            });
            html += `
                <div class="detail-field detail-divider">
                    <span class="label">Ring 3 · 敏感数据外发</span>
                    <div class="value">
                        ${flow.passed ? '通过' : '阻断'} ·
                        接收方 ${this._escapeHtml(
                            destinationLabels[flow.destination_state]
                            || flow.destination_state
                            || '未检查'
                        )}<br>
                        敏感等级 ${this._escapeHtml(
                            riskLabels.confidentialityLabel
                                ? riskLabels.confidentialityLabel(
                                    flow.confidentiality
                                )
                                : flow.confidentiality || '-'
                        )} / 上限 ${this._escapeHtml(
                            riskLabels.confidentialityLabel
                                ? riskLabels.confidentialityLabel(
                                    flow.max_confidentiality
                                )
                                : flow.max_confidentiality || '-'
                        )}<br>
                        来源完整性：${this._escapeHtml(
                            riskLabels.provenanceStateLabel
                                ? riskLabels.provenanceStateLabel(
                                    flow.provenance_state
                                )
                                : flow.provenance_state || '未知'
                        )}<br>
                        接收方值：${this._escapeHtml(
                            (flow.destinations || []).join(', ') || '-'
                        )}<br>
                        实际数据来源：${this._escapeHtml(
                            (flow.data_sources || []).join(', ') || '用户输入'
                        )}<br>
                        来源祖先：${this._escapeHtml(
                            (flow.provenance_ancestors || []).join(', ') || '-'
                        )}<br>
                        授权数据来源：${this._escapeHtml(
                            (flow.allowed_data_sources || []).join(', ') || '-'
                        )}
                    </div>
                </div>
            `;
            if (flowSources.length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">参数来源</span>
                        <div class="value">${flowSources
                            .map(item => this._escapeHtml(item))
                            .join('<br>')}</div>
                    </div>
                `;
            }
            if (resolutions.length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">占位符解析</span>
                        <div class="value">${resolutions
                            .map(item => this._escapeHtml(item))
                            .join('<br>')}</div>
                    </div>
                `;
            }
            if (generationRows.length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">参数生成说明</span>
                        <div class="value">${generationRows
                            .map(item => this._escapeHtml(item))
                            .join('<br>')}</div>
                    </div>
                `;
            }
            if ((d.parameter_resolution_warnings || []).length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">来源提示</span>
                        <div class="value">${d.parameter_resolution_warnings
                            .map(item => this._escapeHtml(item))
                            .join('<br>')}</div>
                    </div>
                `;
            }
        }
        if (d.type === 'HumanAuthorization') {
            const authStatus = String(d.status || 'pending').toLowerCase();
            const chain = d.chain_check || {};
            const flow = d.flow_check || {};
            html += `
                <div class="detail-field">
                    <span class="label">人工授权状态</span>
                    <div class="value">${this._escapeHtml(this._authorizationStatusLabel(authStatus))}</div>
                </div>
                <div class="detail-field">
                    <span class="label">授权调用链</span>
                    <div class="value">${this._escapeHtml(
                        riskLabels.hasChinese?.(chain.reason)
                            ? chain.reason
                            : (
                                chain.consistent === false
                                    ? '调用链检查未通过，该操作与授权计划不一致。'
                                    : '调用链检查通过，该操作与当前计划一致。'
                            )
                    )}</div>
                </div>
                <div class="detail-field">
                    <span class="label">外发数据检查</span>
                    <div class="value">${this._escapeHtml(
                        flow.passed
                            ? '通过'
                            : (
                                riskLabels.hasChinese?.(flow.reason)
                                    ? flow.reason
                                    : '未通过数据外发检查'
                            )
                    )} · ${this._escapeHtml(
                        (flow.data_sources || []).join(', ') || '用户输入'
                    )}</div>
                </div>
            `;
            if (authStatus === 'pending') {
                html += `
                    <div class="manual-authorization-box" data-request-id="${this._escapeHtml(d.request_id || '')}">
                        <div class="manual-authorization-title">等待人工决策</div>
                        <p>批准只对当前计划版本和当前参数生效。</p>
                        <div class="manual-authorization-actions">
                            <button type="button" class="manual-auth-reject">拒绝并阻断</button>
                            <button type="button" class="manual-auth-approve">批准本次操作</button>
                        </div>
                    </div>
                `;
            }
        }

        // DomainData 节点显示角色
        if (d.type === 'DomainData' && d.operation) {
            const role = roleLabels[d.operation] || { label: '数据', color: 'var(--text-primary)' };
            html += `
                <div class="detail-field">
                    <span class="label">角色</span>
                    <div class="value" style="color:${role.color};font-weight:600;">${role.label}</div>
                </div>
            `;

            // 环境变更节点显示实体类型
            if ((d.operation === 'created' || d.operation === 'updated') && d.entity_type) {
                html += `
                    <div class="detail-field">
                        <span class="label">实体类型</span>
                        <div class="value">${d.entity_type}</div>
                    </div>
                `;
            }

            // 环境变更节点显示来源工具（通过入边查找）
            if (d.operation === 'created' || d.operation === 'updated') {
                const sourceEdges = this.links.filter(l => {
                    const targetId = l.target ? (l.target.id || l.target) : null;
                    return targetId === d.id && l.relation === 'produces';
                });
                if (sourceEdges.length > 0) {
                    const source = sourceEdges[0].source;
                    const sourceLabel = source.label || source.id || 'unknown';
                    html += `
                        <div class="detail-field">
                            <span class="label">来源工具</span>
                            <div class="value">${sourceLabel}</div>
                        </div>
                    `;
                }
                html += `
                    <div class="detail-field">
                        <span class="label">环境审计</span>
                        <div class="value">
                            <button type="button" class="storage-jump-btn" data-storage-node="${this._escapeHtml(d.id || '')}">
                                查看字段级环境变更
                            </button>
                        </div>
                    </div>
                `;
            }
        }

        // AgentTool 节点显示操作摘要
        if (d.type === 'AgentTool') {
            // 找出关联的输入/输出边
            const inEdges = this.links.filter(l => {
                const sourceId = l.source ? (l.source.id || l.source) : null;
                return sourceId === d.id && l.relation === 'used';
            });
            const outEdges = this.links.filter(l => {
                const sourceId = l.source ? (l.source.id || l.source) : null;
                return sourceId === d.id && l.relation === 'produces';
            });
            html += `
                <div class="detail-field">
                    <span class="label">操作摘要</span>
                    <div class="value">
                        ${inEdges.length > 0 ? `读取 ${inEdges.length} 个输入` : '无输入'}
                        <br>
                        ${outEdges.length > 0 ? `产出 ${outEdges.length} 个输出` : '无输出'}
                    </div>
                </div>
            `;
        }

        // AIModelInvocation 节点显示关联的工具调用
        if (d.type === 'AIModelInvocation') {
            const toolEdges = this.links.filter(l => {
                const sourceId = l.source ? (l.source.id || l.source) : null;
                return sourceId === d.id && l.relation === 'informed';
            });
            if (toolEdges.length > 0) {
                html += `
                    <div class="detail-field">
                        <span class="label">触发的操作</span>
                        <div class="value">
                            ${toolEdges.map(e => {
                                const target = e.target;
                                const targetLabel = target.label || target.id || 'unknown';
                                return `<span class="tool-chip">${targetLabel}</span>`;
                            }).join(' ')}
                        </div>
                    </div>
                `;
            }
        }

        // 输出结果节点不显示名称
        if (!(d.type === 'DomainData' && d.operation === 'output')) {
            html += `
                <div class="detail-field">
                    <span class="label">名称</span>
                    <div class="value">${d.label || d.id}</div>
                </div>
            `;
        }

        if (d.app) {
            const appDomain = this._canonicalApp(d);
            const rawModule = d.module || (d.app !== appDomain ? d.app : '');
            html += `
                <div class="detail-field">
                    <span class="label">APP 域</span>
                    <div class="value">${this._escapeHtml(this._appLabel(appDomain))}</div>
                </div>
            `;
            if (rawModule) {
                html += `
                    <div class="detail-field">
                        <span class="label">工具模块</span>
                        <div class="value">${this._escapeHtml(rawModule)}</div>
                    </div>
                `;
            }
        }

        if (d.is_sensitive) {
            html += `
                <div class="detail-field">
                    <span class="label">敏感数据</span>
                    <div class="value" style="color:var(--accent-red);font-weight:600;">包含敏感信息</div>
                </div>
            `;
        }

        const flowLabel = d.flow_label || {};
        const confidentiality = flowLabel.confidentiality || {};
        const integrity = flowLabel.integrity || {};
        if (confidentiality.level || integrity.kind) {
            const categoryBadges = (confidentiality.categories || [])
                .map(category => `<span class="tool-chip">${this._escapeHtml(
                    riskLabels.categoryLabel
                        ? riskLabels.categoryLabel(category)
                        : category
                )}</span>`)
                .join(' ');
            html += `
                <div class="detail-field">
                    <span class="label">信息流标签</span>
                    <div class="value">
                        <span class="flow-tag conf-${this._escapeHtml(confidentiality.level || 'public')}">
                            敏感等级 · ${this._escapeHtml(
                                riskLabels.confidentialityLabel
                                    ? riskLabels.confidentialityLabel(
                                        confidentiality.level || 'public'
                                    )
                                    : confidentiality.level || '公开'
                            )}
                        </span>
                        <span class="flow-tag integ-${this._escapeHtml(integrity.kind || 'trusted')}">
                            数据可信度 · ${this._escapeHtml(
                                riskLabels.integrityLabel
                                    ? riskLabels.integrityLabel(
                                        integrity.kind || 'trusted'
                                    )
                                    : integrity.kind || '可信'
                            )}
                        </span>
                        ${categoryBadges}
                    </div>
                </div>
            `;
        }

        if ((integrity.taint_roots || []).length) {
            html += `
                <div class="detail-field">
                    <span class="label">污染来源</span>
                    <div class="value">${this._escapeHtml((integrity.taint_roots || []).join(', '))}</div>
                </div>
            `;
        }

        const injection = flowLabel.injection || {};
        if (this._isInjectionRisky(d)) {
            const fieldStatuses = injection.field_statuses || {};
            const statusText = Object.entries(fieldStatuses)
                .slice(0, 8)
                .map(([path, status]) => (
                    `${path}: ${
                        riskLabels.injectionStatusLabel
                            ? riskLabels.injectionStatusLabel(status)
                            : status
                    }`
                ))
                .join('；');
            html += `
                <div class="detail-field">
                    <span class="label">注入检测</span>
                    <div class="value">
                        <span class="flow-tag ${this._isInjectionRisky(d) ? 'integ-tainted' : ''}">
                            ${this._hasDirectInjectionQuarantine(d)
                                ? '来源已触发隔离'
                                : '来源存在潜在风险'}
                        </span>
                        ${injection.detector ? `<span class="tool-chip">${this._escapeHtml(injection.detector)}</span>` : ''}
                        ${injection.max_score != null ? `<span class="tool-chip">注入评分 ${this._escapeHtml(injection.max_score)}</span>` : ''}
                        ${statusText ? `<div class="detail-value-long">${this._escapeHtml(statusText)}</div>` : ''}
                    </div>
                </div>
            `;
        }

        if (d.blocked) {
            html += `
                <div class="detail-field">
                    <span class="label">阻断状态</span>
                    <div class="value blocked">已阻断</div>
                </div>
                <div class="detail-field">
                    <span class="label">阻断原因</span>
                    <div class="value blocked">安全策略已阻断该操作。</div>
                </div>
            `;
        }

        if (d.decision || d.state) {
            html += `
                <div class="detail-field">
                    <span class="label">${d.type === 'TaskState' ? '状态' : '风险决策'}</span>
                    <div class="value">${this._escapeHtml(
                        d.type === 'TaskState'
                            ? (
                                riskLabels.taskStateLabel
                                    ? riskLabels.taskStateLabel(d.state)
                                    : d.state
                            )
                            : (
                                riskLabels.decisionLabels?.[
                                    String(d.decision || '').toUpperCase()
                                ] || d.decision || d.state
                            )
                    )}</div>
                </div>
            `;
        }

        const sensitiveContent = this._isSensitiveNode(d);
        if (d.inputs) {
            html += this._sensitiveDetailBlock(
                '输入参数',
                d.inputs,
                sensitiveContent,
                true,
            );
        }

        if (d.content) {
            html += this._sensitiveDetailBlock(
                '内容',
                d.content,
                sensitiveContent,
                true,
            );
        }

        if (d.prompt) {
            html += this._sensitiveDetailBlock(
                'Prompt',
                d.prompt,
                sensitiveContent,
                true,
            );
        }

        if (d.prompt_modified && d.raw_prompt && d.raw_prompt !== d.prompt) {
            html += `
                <div class="detail-field detail-divider">
                    <span class="label">原始 Prompt · 审计证据</span>
                    <div class="value detail-value-long prompt-audit-original">${this._escapeHtml(d.raw_prompt)}</div>
                </div>
            `;
        }

        if (d.response) {
            html += this._sensitiveDetailBlock(
                '响应',
                d.response,
                sensitiveContent,
                true,
            );
        }

        // 关联边摘要
        const inEdges = this.links.filter(l => {
            const targetId = l.target ? (l.target.id || l.target) : null;
            return targetId === d.id;
        });
        const outEdges = this.links.filter(l => {
            const sourceId = l.source ? (l.source.id || l.source) : null;
            return sourceId === d.id;
        });

        if (inEdges.length > 0 || outEdges.length > 0) {
            html += `<div class="detail-field detail-divider">
                <span class="label">关联边</span>
                <div class="value edge-list">`;

            if (inEdges.length > 0) {
                html += inEdges.map(e => {
                    const source = e.source;
                    const sourceLabel = source.label || source.id || 'unknown';
                    const relLabel = this.config.relationLabels[e.relation] || e.relation;
                    const dotColor = this.config.linkColors[e.relation] || '#5a6a7a';
                    return `<div class="edge-row">
                        <span class="edge-dot" style="background:${dotColor};"></span>
                        <span class="edge-label" title="${source.label || source.id || 'unknown'}">${sourceLabel}</span>
                        <span class="edge-arrow">──[${relLabel}]──→</span>
                        <span class="edge-node">本节点</span>
                    </div>`;
                }).join('');
            }

            if (outEdges.length > 0) {
                html += outEdges.map(e => {
                    const target = e.target;
                    const targetLabel = target.label || target.id || 'unknown';
                    const relLabel = this.config.relationLabels[e.relation] || e.relation;
                    const dotColor = this.config.linkColors[e.relation] || '#5a6a7a';
                    return `<div class="edge-row">
                        <span class="edge-dot" style="background:${dotColor};"></span>
                        <span class="edge-node">本节点</span>
                        <span class="edge-arrow">──[${relLabel}]──→</span>
                        <span class="edge-label" title="${target.label || target.id || 'unknown'}">${targetLabel}</span>
                    </div>`;
                }).join('');
            }

            html += `</div></div>`;
        }

        body.innerHTML = html;
        body.querySelector('.storage-jump-btn')?.addEventListener('click', () => {
            if (typeof STORAGE_VIEW !== 'undefined' && STORAGE_VIEW.openNode) {
                STORAGE_VIEW.openNode(d);
            }
        });
        if (d.type === 'HumanAuthorization') {
            this._bindHumanAuthorizationActions(d, body);
        }

        // 显示浮动面板
        panel.style.display = 'flex';
        panel.classList.remove('minimized');
    },

    _bindHumanAuthorizationActions(node, body) {
        const requestId = String(node.request_id || '');
        if (!requestId) return;
        const resolve = async (approved) => {
            const buttons = body.querySelectorAll(
                '.manual-authorization-actions button'
            );
            buttons.forEach((button) => { button.disabled = true; });
            try {
                await API.resolveConfirmation(requestId, approved);
                node.status = approved ? 'approved' : 'rejected';
                node.approved = approved;
                node.label = `人工授权：${this._authorizationStatusLabel(node.status)}`;
                body.querySelector('.manual-authorization-box')?.remove();
                this.g.selectAll('.node')
                    .filter(item => item.id === node.id)
                    .attr('class', this._nodeClass(node));
                this._prepareNodeViews(this.nodes, this.links);
                this.g.selectAll('.node')
                    .filter(item => item.id === node.id)
                    .each(function(item) {
                        GRAPH._updateNodeCard(d3.select(this), item);
                    });
                this.showNodeDetail(node);
                setTimeout(() => {
                    if (typeof GRAPH !== 'undefined') GRAPH.loadData();
                }, 500);
            } catch (err) {
                const box = body.querySelector('.manual-authorization-box');
                if (box) {
                    const message = document.createElement('div');
                    message.className = 'manual-authorization-error';
                    message.textContent = `确认提交失败：${err.message}`;
                    box.appendChild(message);
                }
                buttons.forEach((button) => { button.disabled = false; });
            }
        };
        body.querySelector('.manual-auth-approve')?.addEventListener(
            'click',
            () => resolve(true)
        );
        body.querySelector('.manual-auth-reject')?.addEventListener(
            'click',
            () => resolve(false)
        );
    },

    /**
     * 更新统计面板
     */
    updateStats(summary, riskCardCount, eventCount) {
        if (!summary) return;

        document.getElementById('statNodes').textContent = summary.total_nodes || 0;
        document.getElementById('statEdges').textContent = summary.total_edges || 0;

        const blocksEl = document.getElementById('statBlocks');
        const count = typeof riskCardCount === 'number' ? riskCardCount : 0;
        blocksEl.textContent = count;
        blocksEl.className = count > 0 ? 'stat-value warning' : 'stat-value';

        const eventsEl = document.getElementById('statEvents');
        eventsEl.textContent = typeof eventCount === 'number'
            ? eventCount
            : (summary.total_nodes || 0) + (summary.total_edges || 0);
    },

    /**
     * 更新标签显示
     */
    updateLabels() {
        this.g.selectAll('.node')
            .classed('label-hidden', !this.config.showLabels);
    },

    /**
     * 缩放至适合当前画布
     */
    resetView() {
        const nodes = Array.isArray(this._renderedNodes)
            ? this._renderedNodes
            : this.nodes;
        if (!nodes.length) {
            this.svg.transition().duration(300).call(
                this.zoomBehavior.transform,
                d3.zoomIdentity
            );
            return;
        }

        let minX = Infinity;
        let minY = Infinity;
        let maxX = -Infinity;
        let maxY = -Infinity;

        nodes.forEach((node) => {
            const view = node.__view || { width: 96, height: 46 };
            minX = Math.min(minX, (node.x || 0) - view.width / 2);
            maxX = Math.max(maxX, (node.x || 0) + view.width / 2);
            minY = Math.min(minY, (node.y || 0) - view.height / 2);
            maxY = Math.max(maxY, (node.y || 0) + view.height / 2);
        });

        const padding = 56;
        const contentWidth = Math.max(1, maxX - minX);
        const contentHeight = Math.max(1, maxY - minY);
        const scale = Math.min(
            1.6,
            Math.max(0.25, Math.min(
                (this.config.width - padding * 2) / contentWidth,
                (this.config.height - padding * 2) / contentHeight
            ))
        );
        const centerX = (minX + maxX) / 2;
        const centerY = (minY + maxY) / 2;
        const transform = d3.zoomIdentity
            .translate(this.config.width / 2 - scale * centerX, this.config.height / 2 - scale * centerY)
            .scale(scale);

        this.svg.transition().duration(400).call(this.zoomBehavior.transform, transform);
    },

    /**
     * 恢复结构化节点位置，清理高亮并适应画布。
     */
    resetLayout() {
        this.clearHighlight();
        this.render();
        requestAnimationFrame(() => this.resetView());
    },

    /**
     * 清理资源
     */
    destroy() {
        if (this.simulation) {
            this.simulation.stop();
        }
    },

    /**
     * 定位并短暂高亮指定节点（用于追踪步骤点击定位）
     */
    flashNode(nodeId) {
        if (!nodeId) return;

        const rendered = Array.isArray(this._renderedNodes)
            ? this._renderedNodes
            : this.nodes;
        const node = rendered.find(n => n.id === nodeId);
        if (!node) {
            console.warn(`[flashNode] 未找到节点: ${nodeId}`);
            return;
        }

        // 将视图居中到该节点
        const transform = d3.zoomIdentity
            .translate(this.config.width / 2, this.config.height / 2)
            .scale(1.5)
            .translate(-node.x, -node.y);

        this.svg.transition().duration(400).call(
            this.zoomBehavior.transform,
            transform
        );

        // 短暂描边高亮
        const nodeEl = this.g.selectAll('.node').filter(n => n.id === nodeId);
        nodeEl.classed('flash', true);
        setTimeout(() => nodeEl.classed('flash', false), 1100);

        this.showNodeDetail(node);
    }
};
