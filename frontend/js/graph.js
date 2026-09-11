/**
 * 拓扑图模块 - 使用 D3.js 渲染 PROV 知识图谱（结构化布局）
 *
 * 功能：
 * - 结构化固定布局：Prompt 节点在左、AIAgent 在中间、右侧按迭代顺序分行展示
 * - 每一行 = 一次 LLM 思考 → 工具调用 → 结果数据
 * - 行与行之间不连线（天然自上而下递进）
 * - 节点颜色/形状按类型编码
 * - 异常节点高亮（红色闪烁）
 * - 拖拽、缩放、平移
 * - 悬停高亮路径
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

    // 配置
    config: {
        width: 0,
        height: 0,
        showLabels: true,
        nodeRadius: {
            'AIAgent': 30,
            'AIModelInvocation': 24,
            'AgentTool': 22,
            'Prompt': 18,
            'DomainData': 20,
        },
        nodeColors: {
            'AIAgent': '#4f8cff',
            'AIModelInvocation': '#3fb950',
            'AgentTool': '#d4862b',
            'Prompt': '#d29922',
            'DomainData': '#a371f7',
        },
        nodeShapes: {
            'AIAgent': 'circle',
            'AIModelInvocation': 'diamond',
            'AgentTool': 'rect',
            'Prompt': 'roundRect',
            'DomainData': 'ellipse',
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

        // 添加缩放行为
        this.svg.call(d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                this.g && this.g.attr('transform', event.transform);
            })
        );

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
                .attr('refX', 20)
                .attr('refY', 0)
                .attr('markerWidth', 8)
                .attr('markerHeight', 8)
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

            this.setData(data.graph.nodes, data.graph.links);
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
    setData(newNodes, newLinks) {
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
     * 渲染拓扑图（结构化布局，增量更新模式）
     */
    render() {
        const self = this;
        const { nodes } = this;

        // 1. 结构化布局：Prompt 左 / AIAgent 中 / 右侧按迭代顺序分行
        this._computeStructuredLayout();

        // 2. 过滤行间连线（行与行之间不连线，天然自上而下递进）
        const links = this._visibleLinks();
        this._renderLinks = links;

        this.simulation.nodes(nodes).force('link').links(links);

        // --- 增量更新边 ---
        const linkGroup = this.g.selectAll('.link-group')
            .data(links, d => `${d.source.id || d.source}→${d.target.id || d.target}:${d.relation}`);

        // 退出：移除旧边
        linkGroup.exit()
            .transition()
            .duration(300)
            .style('opacity', 0)
            .remove();

        // 新增：创建新边
        const linkEnter = linkGroup.enter()
            .append('g')
            .attr('class', 'link-group')
            .style('opacity', 0);

        // 边线
        linkEnter.append('line')
            .attr('class', 'link')
            .attr('stroke', d => self.config.linkColors[d.relation] || '#5a6a7a')
            .attr('stroke-width', 1.5)
            .attr('stroke-dasharray', d => d.relation === 'wasInformedBy' ? '5,3' : 'none')
            .attr('marker-end', d => {
                const arrowRelations = ['used', 'produces', 'wasDerivedFrom', 'informed', 'belongsTo',
                                       // 旧版兼容
                                       'wasGeneratedBy', 'wasInformedBy', 'wasAssociatedWith'];
                if (arrowRelations.includes(d.relation)) {
                    return `url(#arrow-${d.relation})`;
                }
                return null;
            });

        // 边标签
        linkEnter.append('text')
            .attr('class', 'link-label')
            .text(d => self.config.relationLabels[d.relation] || d.relation)
            .attr('dy', -8);

        // 合并
        const link = linkEnter.merge(linkGroup);

        // 新边淡入
        linkEnter.transition()
            .duration(500)
            .style('opacity', 1);

        // --- 增量更新节点 ---
        const node = this.g.selectAll('.node')
            .data(nodes, d => d.id);

        // 退出：移除旧节点
        node.exit()
            .transition()
            .duration(300)
            .style('opacity', 0)
            .remove();

        // 新增：创建新节点
        const nodeEnter = node.enter()
            .append('g')
            .attr('class', d => {
                let cls = 'node';
                if (d.blocked) cls += ' abnormal';
                if (d.is_sensitive) cls += ' sensitive';
                return cls;
            })
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
                    // 拖拽结束后固定在当前位置，直到下一次自动布局
                    d.fx = d.x;
                    d.fy = d.y;
                })
            );

        // 节点形状：节点类型通过形状与颜色编码
        nodeEnter.each(function(d) {
            const el = d3.select(this);
            const r = self.config.nodeRadius[d.type] || 16;
            const color = self.config.nodeColors[d.type] || '#6e7b8a';

            switch (self.config.nodeShapes[d.type]) {
                case 'diamond':
                    el.append('polygon')
                        .attr('points', `0,${-r} ${r},0 0,${r} ${-r},0`)
                        .attr('fill', color);
                    break;
                case 'rect':
                    el.append('rect')
                        .attr('x', -r * 1.2)
                        .attr('y', -r * 0.8)
                        .attr('width', r * 2.4)
                        .attr('height', r * 1.6)
                        .attr('rx', 4)
                        .attr('fill', color);
                    break;
                case 'roundRect':
                    el.append('rect')
                        .attr('x', -r * 1.4)
                        .attr('y', -r * 0.7)
                        .attr('width', r * 2.8)
                        .attr('height', r * 1.4)
                        .attr('rx', r * 0.7)
                        .attr('fill', color);
                    break;
                case 'ellipse':
                    el.append('ellipse')
                        .attr('rx', r * 1.3)
                        .attr('ry', r * 0.9)
                        .attr('fill', color);
                    break;
                default: // circle
                    el.append('circle')
                        .attr('r', r)
                        .attr('fill', color);
            }
        });

        // 节点标签
        nodeEnter.append('text')
            .attr('dy', d => {
                const r = self.config.nodeRadius[d.type] || 16;
                return r + 16;
            })
            .attr('text-anchor', 'middle')
            .text(d => d.type === 'DomainData' && d.operation === 'output' ? '' : (d.label || d.id))
            .attr('class', d => self.config.showLabels ? 'node-label' : 'label-hidden');

        // 合并
        const nodeMerged = nodeEnter.merge(node);

        // 新节点淡入
        nodeEnter.transition()
            .duration(500)
            .style('opacity', 1);

        // 更新现有节点的类
        nodeMerged.attr('class', d => {
            let cls = 'node';
            if (d.blocked) cls += ' abnormal';
            if (d.is_sensitive) cls += ' sensitive';
            return cls;
        });

        // --- 交互事件 ---
        // 悬停高亮路径
        nodeMerged.on('mouseenter', function(event, d) {
            self.highlightPath(d);
        });

        nodeMerged.on('mouseleave', function() {
            self.clearHighlight();
        });

        // 点击查看详情
        nodeMerged.on('click', function(event, d) {
            self.showNodeDetail(d);
        });

        // 边悬停
        link.on('mouseenter', function(event, d) {
            d3.select(this).select('.link').classed('highlighted', true);
        });

        link.on('mouseleave', function() {
            d3.select(this).select('.link').classed('highlighted', false);
        });

        // --- 力导向模拟的 tick 事件（节点位置已固定，主要支撑拖拽） ---
        this.simulation.on('tick', null);
        this.simulation.on('tick', () => {
            // 更新边位置
            link.select('.link')
                .attr('x1', d => d.source ? d.source.x : 0)
                .attr('y1', d => d.source ? d.source.y : 0)
                .attr('x2', d => d.target ? d.target.x : 0)
                .attr('y2', d => d.target ? d.target.y : 0);

            link.select('.link-label')
                .attr('x', d => (d.source && d.target) ? (d.source.x + d.target.x) / 2 : 0)
                .attr('y', d => (d.source && d.target) ? (d.source.y + d.target.y) / 2 : 0);

            // 更新节点位置
            nodeMerged.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);
        });

        // 节点已由 fx/fy 固定，直接按布局位置渲染
        nodeMerged.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);
        link.select('.link')
            .attr('x1', d => d.source ? d.source.x : 0)
            .attr('y1', d => d.source ? d.source.y : 0)
            .attr('x2', d => d.target ? d.target.x : 0)
            .attr('y2', d => d.target ? d.target.y : 0);
        link.select('.link-label')
            .attr('x', d => (d.source && d.target) ? (d.source.x + d.target.x) / 2 : 0)
            .attr('y', d => (d.source && d.target) ? (d.source.y + d.target.y) / 2 : 0);

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

        // 收集工具对应的数据节点（输入 used / 输出 produces）
        const rowResultsFor = (tool) => {
            const outputs = links
                .filter(l => l.source && l.target && l.source.id === tool.id && l.relation === 'produces' && isType(l.target, 'DomainData'))
                .map(l => l.target);
            const inputs = links
                .filter(l => l.source && l.target && l.target.id === tool.id && l.relation === 'used' && isType(l.source, 'DomainData'))
                .map(l => l.source);
            return [...inputs, ...outputs];
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
            const rowTools = [...new Set([...directTools, ...viaDataTools])];
            if (rowTools.length === 0) {
                rows.push({ thought: thought, tool: null, results: [] });
            } else {
                for (const tool of rowTools) {
                    usedTools.add(tool.id);
                    rows.push({ thought: thought, tool: tool, results: rowResultsFor(tool) });
                }
            }
        }

        // 没有关联思考的工具 → 单独成行
        for (const tool of tools) {
            if (usedTools.has(tool.id)) continue;
            rows.push({ thought: null, tool: tool, results: rowResultsFor(tool) });
        }

        // 兜底：没有任何行的数据节点
        const usedData = new Set();
        rows.forEach(r => r.results.forEach(d => usedData.add(d.id)));
        const leftoverData = dataNodes.filter(d => !usedData.has(d.id));
        if (rows.length === 0 && leftoverData.length > 0) {
            rows.push({ thought: null, tool: null, results: leftoverData });
        }

        // 列位置
        const colPrompt = w * 0.10;
        const colAgent = w * 0.30;
        const colThought = w * 0.50;
        const colTool = w * 0.72;
        const colData = w * 0.92;

        const centerY = h / 2;
        const rowCount = Math.max(1, rows.length);
        const rowGap = Math.min(150, Math.max(70, (h * 0.82) / rowCount));
        const rowStart = centerY - (rowGap * (rowCount - 1)) / 2;

        // 行号映射（首次认领，避免同一节点被多个行覆盖归属）
        this._nodeRow = new Map();
        const mark = (n, idx) => { if (n && !this._nodeRow.has(n.id)) this._nodeRow.set(n.id, idx); };

        rows.forEach((row, idx) => {
            mark(row.thought, idx);
            mark(row.tool, idx);
            row.results.forEach(d => mark(d, idx));
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

            const results = row.results.filter(x => x && this._nodeRow.get(x.id) === idx);
            results.forEach((d, k) => {
                const offset = results.length === 1 ? 0 : (k - (results.length - 1) / 2) * 44;
                d.x = colData; d.y = y + offset;
                d.fx = colData; d.fy = y + offset;
            });
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
        const row = this._nodeRow || new Map();
        return this.links.filter(l => {
            const s = l.source ? (l.source.id || l.source) : null;
            const t = l.target ? (l.target.id || l.target) : null;
            const rs = row.get(s);
            const rt = row.get(t);
            // 两个端点都在行内且行号不同 → 隐藏（行间不连线）
            if (rs != null && rt != null && rs !== rt) return false;
            return true;
        });
    },

    /**
     * 高亮节点的关联路径
     */
    highlightPath(d) {
        const nodeId = d.id;

        // 高亮所有关联边
        this.g.selectAll('.link-group')
            .filter(l => {
                const sourceId = l.source ? (l.source.id || l.source) : null;
                const targetId = l.target ? (l.target.id || l.target) : null;
                return sourceId === nodeId || targetId === nodeId;
            })
            .select('.link')
            .classed('highlighted', true);

        // 高亮关联节点
        this.g.selectAll('.node')
            .filter(n => {
                if (n.id === nodeId) return true;
                return this.links.some(l => {
                    const sourceId = l.source ? (l.source.id || l.source) : null;
                    const targetId = l.target ? (l.target.id || l.target) : null;
                    return (sourceId === nodeId && targetId === n.id) ||
                           (targetId === nodeId && sourceId === n.id);
                });
            })
            .select('circle, polygon, rect, ellipse')
            .attr('stroke-width', 4);
    },

    /**
     * 清除高亮
     */
    clearHighlight() {
        this.g.selectAll('.link-group').select('.link').classed('highlighted', false);
        this.g.selectAll('.node').select('circle, polygon, rect, ellipse')
            .attr('stroke-width', 2);
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
            html += `
                <div class="detail-field">
                    <span class="label">所属 APP</span>
                    <div class="value">${d.app}</div>
                </div>
            `;
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
        this.g.selectAll('.node .node-label')
            .attr('class', d => this.config.showLabels ? 'node-label' : 'label-hidden');
    },

    /**
     * 重置视图
     */
    resetView() {
        this.svg.transition().duration(500).call(
            d3.zoom().transform,
            d3.zoomIdentity
        );
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
            d3.zoom().transform,
            transform
        );

        // 形状元素短暂描边高亮
        const shapeEl = this.g.selectAll('.node')
            .filter(n => n.id === nodeId)
            .select('circle, polygon, rect, ellipse');

        if (!shapeEl.empty()) {
            shapeEl
                .transition().duration(120)
                .attr('stroke', '#f85149')
                .attr('stroke-width', 4)
                .transition().delay(650).duration(350)
                .attr('stroke', '#0d1117')
                .attr('stroke-width', 1.5);
        }

        this.showNodeDetail(node);
    }
};
