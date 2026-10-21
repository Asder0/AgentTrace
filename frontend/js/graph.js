/**
 * 拓扑图模块 - 使用 D3.js 渲染 PROV 知识图谱（结构化布局）
 *
 * 功能：
 * - 结构化布局：提示词 → 智能体 → 推理 → 输入数据 → 工具调用 → 输出数据
 * - 卡片式节点：类型 / 标题 / 摘要分层展示
 * - 列标题与迭代轮次（R1、R2…）引导
 * - 关系分色、归属边可开关、悬停聚焦关联路径
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

    // 配置
    config: {
        width: 0,
        height: 0,
        showLabels: true,
        showBelongsTo: true,
        maxCardWidth: 200,
        typeLabels: {
            'AIAgent': '智能体',
            'AIModelInvocation': 'LLM 推理',
            'AgentTool': '工具调用',
            'Prompt': '用户提示',
            'DomainData': '数据实体',
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
        appLabels: {
            'system': '系统',
            'unified': '统一',
            'banking': '银行',
            'workspace': '办公',
            'slack': '通讯',
            'travel': '旅行',
        },
        suiteLabels: {
            'banking': '银行套件',
            'workspace': '办公套件',
            'slack': '通讯套件',
            'travel': '旅行套件',
        },
        nodeColors: {
            'AIAgent': '#4f8cff',
            'AIModelInvocation': '#3fb950',
            'AgentTool': '#d4862b',
            'Prompt': '#d29922',
            'DomainData': '#a371f7',
        },
        linkColors: {
            'belongsTo': '#4f8cff',
            'informed': '#3fb950',
            'used': '#d4862b',
            'produces': '#a371f7',
            'wasDerivedFrom': '#f85149',
            // 旧版兼容（保留但不再使用）
            'wasAssociatedWith': '#4f8cff',
            'wasInformedBy': '#3fb950',
            'wasGeneratedBy': '#a371f7',
            'wasAttributedTo': '#d29922',
        },
        // 关系的中文标签
        relationLabels: {
            'belongsTo': '归属',
            'informed': '通知',
            'used': '读取',
            'produces': '产出',
            'wasDerivedFrom': '派生',
            // 旧版兼容
            'wasAssociatedWith': '归属',
            'wasInformedBy': '通知',
            'wasGeneratedBy': '产出',
            'wasAttributedTo': '归属',
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
                this._computeStructuredLayout();
                this.render();
            }
        });

        // 绑定控制按钮
        document.getElementById('btnReset').addEventListener('click', () => this.resetView());
        document.getElementById('btnAutoLayout').addEventListener('click', () => this.autoLayout());
        document.getElementById('chkShowLabels').addEventListener('change', (e) => {
            this.config.showLabels = e.target.checked;
            this.updateLabels();
        });

        const belongsToggle = document.getElementById('chkShowBelongsTo');
        if (belongsToggle) {
            belongsToggle.addEventListener('change', (e) => {
                this.config.showBelongsTo = e.target.checked;
                this.render();
            });
        }
    },

    /**
     * 添加 SVG defs（箭头、滤镜）
     */
    _addDefs() {
        // 箭头定义
        const arrowTypes = ['used', 'produces', 'wasDerivedFrom', 'informed', 'belongsTo',
                           // 旧版兼容
                           'wasGeneratedBy', 'wasInformedBy', 'wasAssociatedWith'];
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

        // 重建 nodeMap
        this.nodeMap = new Map();
        newNodes.forEach(n => this.nodeMap.set(n.id, n));

        // 确保 links 中的 source/target 引用 nodeMap 中的对象
        newLinks.forEach(link => {
            const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
            const targetId = typeof link.target === 'object' ? link.target.id : link.target;

            link.source = this.nodeMap.get(sourceId) || { id: sourceId, x: 0, y: 0 };
            link.target = this.nodeMap.get(targetId) || { id: targetId, x: 0, y: 0 };
        });

        this.nodes = newNodes;
        this.links = newLinks;

        console.log(`[graph] ${this.nodes.length} 节点, ${this.links.length} 边`);
    },

    /**
     * 生成节点的卡片化展示信息（类型 / 标题 / 摘要 / 尺寸）。
     */
    _prepareNodeViews() {
        const { nodes, links } = this;
        const maxWidth = Math.max(96, Math.min(
            this.config.maxCardWidth,
            (this.config.width || 1200) * 0.17 - 12
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
            const typeName = this.config.typeLabels[node.type] || node.type;
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
                subtitle = node.module || node.app || '';
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
                } else {
                    title = '数据实体';
                    subtitle = this._formatDataLabel(node.label) || node.entity_type || '';
                }
            }

            const charWidth = node.type === 'AgentTool' ? 5.8 : 6.4;
            const longest = Math.max(title.length, subtitle.length);
            const headWidth = typeName.length * 6.6 + (appText ? appText.length * 5.6 + 18 : 0) + 24;
            const width = Math.max(96, Math.min(
                maxWidth,
                Math.round(Math.max(longest * charWidth + 34, headWidth))
            ));
            const titleChars = Math.max(8, Math.floor((width - 32) / charWidth));
            const subtitleChars = Math.max(10, Math.floor((width - 32) / 5.4));
            const viewTitle = this._shortText(title, titleChars);
            const viewSubtitle = this._shortText(subtitle, subtitleChars);

            node.__view = {
                title: viewTitle,
                subtitle: viewSubtitle,
                full: node.label || node.id || title,
                typeName,
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
        };
        return map[relation] || 'other';
    },

    _nodeClass(node) {
        let cls = `node type-${String(node.type || 'unknown').toLowerCase()}`;
        if (node.blocked) cls += ' abnormal';
        if (node.is_sensitive) cls += ' sensitive';
        if (!this.config.showLabels) cls += ' label-hidden';
        return cls;
    },

    _linkGroupClass(link) {
        let cls = `link-group link-${this._relationClass(link.relation)}`;
        if (this._isContextLink(link)) cls += ' link-context';
        if (this._isCrossAppLink(link)) cls += ' link-cross-app';
        return cls;
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
        return this.config.appLabels[key] || key || '未知';
    },

    /**
     * 把旧的模块级 app 名（file_reader/email/calendar 等）兼容为 suite 级 APP 域。
     */
    _canonicalApp(node) {
        const moduleName = String((node && node.module) || '').trim();
        const raw = String((node && node.app) || '').trim();
        const suites = ['system', 'banking', 'workspace', 'slack', 'travel'];
        const moduleSuites = {
            'system': ['system'],
            'banking': ['banking'],
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
        const contextSuite = String((node && node.suite) || this._contextSuite || '').trim();

        const resolve = (key) => {
            if (!key) return null;
            if (suites.includes(key)) return key;
            const owners = moduleSuites[key] || [];
            if (contextSuite && owners.includes(contextSuite)) return contextSuite;
            if (owners.length === 1) return owners[0];
            if (owners.length > 1) return 'unified';
            return null;
        };

        // 旧 trace 被 suite 级归一时会保留 module，优先使用 module
        return resolve(moduleName) || resolve(raw) || raw || 'unknown';
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
        const relation = this.config.relationLabels[link.relation] || link.relation;
        return this._isCrossAppLink(link) ? `跨 APP · ${relation}` : relation;
    },

    /**
     * 计算从节点中心指向目标方向时，卡片边界上的交点。
     */
    _boundaryPoint(from, to) {
        const view = (from && from.__view) || { width: 96, height: 40 };
        const dx = (to.x || 0) - (from.x || 0);
        const dy = (to.y || 0) - (from.y || 0);
        const hw = view.width / 2 || 48;
        const hh = view.height / 2 || 20;
        const scale = 1 / Math.max(Math.abs(dx) / hw, Math.abs(dy) / hh, 1e-6);
        return {
            x: (from.x || 0) + dx * scale,
            y: (from.y || 0) + dy * scale,
        };
    },

    /**
     * 生成曲线路径，并记录标签位置。
     */
    _linkPath(link) {
        if (!link.source || !link.target) return '';
        const s = this._boundaryPoint(link.source, link.target);
        const t = this._boundaryPoint(link.target, link.source);
        const dx = t.x - s.x;
        const dy = t.y - s.y;
        const distance = Math.hypot(dx, dy) || 1;
        const curvature = link.relation === 'belongsTo' ? 0.08 : (this._isContextLink(link) ? 0.06 : 0.12);
        const cx = (s.x + t.x) / 2 - dy * curvature;
        const cy = (s.y + t.y) / 2 + dx * curvature;

        link.__labelPoint = {
            x: (s.x + 2 * cx + t.x) / 4,
            y: (s.y + 2 * cy + t.y) / 4,
        };

        return `M${s.x.toFixed(1)},${s.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${t.x.toFixed(1)},${t.y.toFixed(1)}`;
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
            .text(view.typeName);

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
                arrow.className = 'app-flow-arrow';
                arrow.setAttribute('aria-hidden', 'true');
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
        const relatedLinks = new Set();

        this.links.forEach((link) => {
            const sourceId = link.source ? (link.source.id || link.source) : null;
            const targetId = link.target ? (link.target.id || link.target) : null;
            if (sourceId === node.id || targetId === node.id) {
                relatedLinks.add(link);
                relatedNodes.add(sourceId);
                relatedNodes.add(targetId);
            }
        });

        this.g.selectAll('.node')
            .classed('dimmed', n => !relatedNodes.has(n.id))
            .classed('focused', n => n.id === node.id);

        this.g.selectAll('.link-group')
            .classed('dimmed', l => !relatedLinks.has(l))
            .classed('highlighted', l => relatedLinks.has(l));
    },

    /**
     * 悬停边：只聚焦这条边及其两端节点。
     */
    _focusLink(link) {
        const sourceId = link.source ? (link.source.id || link.source) : null;
        const targetId = link.target ? (link.target.id || link.target) : null;

        this.g.selectAll('.link-group')
            .classed('dimmed', l => l !== link)
            .classed('highlighted', l => l === link);

        this.g.selectAll('.node')
            .classed('dimmed', n => n.id !== sourceId && n.id !== targetId)
            .classed('focused', n => n.id === sourceId || n.id === targetId);
    },

    /**
     * 渲染拓扑图（结构化布局，增量更新模式）
     */
    render() {
        const self = this;
        const { nodes } = this;

        // 1. 生成节点卡片信息并计算结构化布局
        this._prepareNodeViews();
        this._computeStructuredLayout();

        // 2. 绘制列标题与迭代行背景
        this._renderStageGuides();
        this._renderAppFlow();

        // 3. 过滤行间连线
        const links = this._visibleLinks();
        this._renderLinks = links;

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
    },

    /**
     * 计算结构化布局
     * Prompt 节点在左、AIAgent 在中间、右侧从上到下每一行 = 一次思考 → 工具调用 → 结果
     */
    _computeStructuredLayout() {
        const w = this.config.width || 1200;
        const h = this.config.height || 800;

        const { nodes, links } = this;
        const isType = (n, t) => n && n.type === t;

        const prompts = nodes.filter(n => isType(n, 'Prompt'));
        const agents = nodes.filter(n => isType(n, 'AIAgent'));
        const thoughts = nodes.filter(n => isType(n, 'AIModelInvocation'));
        const tools = nodes.filter(n => isType(n, 'AgentTool'));
        const dataNodes = nodes.filter(n => isType(n, 'DomainData'));
        // 图谱节点按捕获顺序排列，可用于恢复工具的真实执行顺序
        const nodeOrder = new Map(nodes.map((node, index) => [node.id, index]));

        // 收集工具对应的数据节点（输入 used / 输出 produces）
        const rowResultsFor = (tool) => {
            const outputs = links
                .filter(l => l.source && l.target && l.source.id === tool.id && l.relation === 'produces' && isType(l.target, 'DomainData'))
                .map(l => l.target);
            const inputs = links
                .filter(l => l.source && l.target && l.target.id === tool.id && l.relation === 'used' && isType(l.source, 'DomainData'))
                .map(l => l.source);
            return {
                inputs: [...new Set(inputs)],
                outputs: [...new Set(outputs)],
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
            // 有输入数据时：思考 → informed → 输入数据 → used → 工具
            const viaDataTools = links
                .filter(l => l.source && l.target && l.source.id === thought.id && l.relation === 'informed' && isType(l.target, 'DomainData'))
                .map(l => l.target)
                .flatMap(dataNode =>
                    links
                        .filter(l => l.source && l.target && l.source.id === dataNode.id && l.relation === 'used' && isType(l.target, 'AgentTool'))
                        .map(l => l.target)
                );
            const rowTools = [...new Set([...directTools, ...viaDataTools])]
                .sort((a, b) => (nodeOrder.get(a.id) ?? 0) - (nodeOrder.get(b.id) ?? 0));
            if (rowTools.length === 0) {
                rows.push({ thought, tool: null, inputs: [], outputs: [] });
            } else {
                for (const tool of rowTools) {
                    usedTools.add(tool.id);
                    const results = rowResultsFor(tool);
                    rows.push({
                        thought,
                        tool,
                        inputs: results.inputs,
                        outputs: results.outputs,
                    });
                }
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
            });
        }

        // 兜底：没有任何行的数据节点
        const usedData = new Set();
        rows.forEach(r => {
            r.inputs.forEach(d => usedData.add(d.id));
            r.outputs.forEach(d => usedData.add(d.id));
        });
        const leftoverData = dataNodes.filter(d => !usedData.has(d.id));
        if (rows.length === 0 && leftoverData.length > 0) {
            rows.push({ thought: null, tool: null, inputs: leftoverData, outputs: [] });
        }

        // 列位置：提示词 → 智能体 → 推理 → 输入数据 → 工具 → 输出数据
        const colPrompt = w * 0.08;
        const colAgent = w * 0.24;
        const colThought = w * 0.40;
        const colInput = w * 0.56;
        const colTool = w * 0.72;
        const colOutput = w * 0.88;

        this._columns = [
            { key: 'prompt', x: colPrompt, label: '提示词' },
            { key: 'agent', x: colAgent, label: '智能体' },
            { key: 'thought', x: colThought, label: '推理' },
            { key: 'input', x: colInput, label: '输入数据' },
            { key: 'tool', x: colTool, label: '工具调用' },
            { key: 'output', x: colOutput, label: '输出数据' },
        ];

        const topMargin = 64;
        const bottomMargin = 24;
        const rowCount = Math.max(1, rows.length);
        const usableHeight = Math.max(160, h - topMargin - bottomMargin);
        const rowGap = Math.min(132, Math.max(64, usableHeight / rowCount));
        const rowStart = topMargin + Math.max(0, (usableHeight - rowGap * (rowCount - 1)) / 2);
        const centerY = topMargin + usableHeight / 2;

        // 行背景与行号的几何信息
        const bandLeft = colThought - 64;
        this._rows = rows.map((row, idx) => ({
            idx,
            thought: row.thought,
            tool: row.tool,
            inputs: row.inputs,
            outputs: row.outputs,
            y: rowStart + idx * rowGap,
            left: bandLeft,
            top: rowStart + idx * rowGap - rowGap / 2 + 5,
            width: Math.max(140, w - 14 - bandLeft),
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
                    const offset = claimed.length === 1 ? 0 : (k - (claimed.length - 1) / 2) * 54;
                    d.x = x; d.y = y + offset;
                    d.fx = x; d.fy = y + offset;
                });
            };
            placeColumn(row.inputs, colInput);
            placeColumn(row.outputs, colOutput);
        });

        // 兜底：未被布局的节点
        const assigned = new Set(nodes.filter(n => n.fx != null).map(n => n.id));
        nodes.forEach(n => {
            if (!assigned.has(n.id)) {
                n.x = colThought; n.y = centerY;
                n.fx = colThought; n.fy = centerY;
            }
        });
    },

    /**
     * 过滤行间连线：行与行之间不连线（天然自上而下递进）
     */
    _visibleLinks() {
        return this.links.filter(l => {
            // 归属边默认弱化显示，可按需关闭，减少中心区域的放射状连线
            if (!this.config.showBelongsTo
                && (l.relation === 'belongsTo'
                    || l.relation === 'wasAssociatedWith'
                    || l.relation === 'wasAttributedTo')) {
                return false;
            }
            return true;
        });
    },

    /**
     * 高亮节点的关联路径
     */
    highlightPath(d) {
        this._focusNode(d);
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
            .classed('highlighted', false);
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
        const panel = document.getElementById('nodeDetailPanel');
        const body = document.getElementById('nodeDetailBody');

        if (!panel || !body) return;

        const typeLabels = {
            'AIAgent': 'AI 智能体',
            'AIModelInvocation': 'LLM 推理',
            'AgentTool': '工具调用',
            'Prompt': '提示内容',
            'DomainData': '数据实体',
        };

        // 角色标签映射（根据 operation 字段）
        const roleLabels = {
            'input': { label: '输入参数', color: 'var(--accent-blue)' },
            'output': { label: '输出结果', color: 'var(--accent-green)' },
            'created': { label: '环境变更 - 创建', color: 'var(--accent-orange)' },
            'updated': { label: '环境变更 - 更新', color: 'var(--accent-yellow)' },
        };

        let html = `
            <div class="detail-field">
                <span class="label">类型</span>
                <div class="value">${typeLabels[d.type] || d.type}</div>
            </div>
        `;

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

        if (d.blocked) {
            html += `
                <div class="detail-field">
                    <span class="label">阻断状态</span>
                    <div class="value blocked">已阻断</div>
                </div>
                <div class="detail-field">
                    <span class="label">阻断原因</span>
                    <div class="value blocked">${d.block_reason || '未知'}</div>
                </div>
            `;
        }

        if (d.inputs) {
            html += `
                <div class="detail-field">
                    <span class="label">输入参数</span>
                    <div class="value">${d.inputs}</div>
                </div>
            `;
        }

        if (d.content) {
            html += `
                <div class="detail-field">
                    <span class="label">内容</span>
                    <div class="value">${d.content}</div>
                </div>
            `;
        }

        if (d.prompt) {
            html += `
                <div class="detail-field">
                    <span class="label">Prompt</span>
                    <div class="value detail-value-long">${d.prompt}</div>
                </div>
            `;
        }

        if (d.response) {
            html += `
                <div class="detail-field">
                    <span class="label">响应</span>
                    <div class="value detail-value-long">${d.response}</div>
                </div>
            `;
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

        // 显示浮动面板
        panel.style.display = 'flex';
        panel.classList.remove('minimized');
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
        if (!this.nodes.length) {
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

        this.nodes.forEach((node) => {
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
     * 自动布局（重新计算结构化布局）
     */
    autoLayout() {
        this._computeStructuredLayout();
        this.render();
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

        const node = this.nodes.find(n => n.id === nodeId);
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
