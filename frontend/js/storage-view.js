/**
 * 环境变更视图：以字段差异为中心展示四个 APP 的真实环境状态变化。
 * 完整初始/当前快照仍可在同一页面中切换查看。
 */

const STORAGE_VIEW = {
    _initialized: false,
    _active: false,
    _dirty: true,
    _suites: [],
    _suite: null,
    _mode: 'diff',
    _onlyChanges: false,
    _search: '',
    _timer: null,
    _detail: null,
    _selectedChange: null,
    _snapshotKey: '',
    _searchTimer: null,
    _graphEvidence: [],
    _pendingNodeId: null,
    _pendingTool: null,
    _traceSnapshots: null,
    _traceContext: null,
    _traceLegacy: false,
    _expandedChangeGroups: new Set(),

    init() {
        if (this._initialized) return;
        this._initialized = true;

        this.el = {
            view: document.getElementById('storageView'),
            suiteTabs: document.getElementById('storageSuiteTabs'),
            summary: document.getElementById('storageSummary'),
            changeList: document.getElementById('storageChangeList'),
            changeCount: document.getElementById('storageChangeCount'),
            diffBody: document.getElementById('storageDiffBody'),
            tree: document.getElementById('storageTree'),
            breadcrumb: document.getElementById('storageBreadcrumb'),
            status: document.getElementById('storageStatus'),
            search: document.getElementById('storageSearch'),
            onlyChanges: document.getElementById('storageOnlyChanges'),
            autoRefresh: document.getElementById('storageAutoRefresh'),
            refreshBtn: document.getElementById('storageRefreshBtn'),
            locateGraph: document.getElementById('storageLocateGraph'),
        };

        this._bindEvents();
        this.loadSuites();
    },

    _bindEvents() {
        this.el.suiteTabs?.addEventListener('click', (event) => {
            const button = event.target.closest('.storage-suite-tab');
            if (button) this.loadSuite(button.dataset.suite);
        });

        document.getElementById('storageMode')?.addEventListener('click', (event) => {
            const button = event.target.closest('.storage-mode-btn');
            if (!button) return;
            this._mode = button.dataset.mode || 'diff';
            this._selectedChange = null;
            this._render();
        });

        this.el.onlyChanges?.addEventListener('change', () => {
            this._onlyChanges = this.el.onlyChanges.checked;
            this._render();
        });

        this.el.autoRefresh?.addEventListener('change', () => {
            if (this.el.autoRefresh.checked && this._active) {
                this.refresh();
                this._startAutoRefresh();
            } else {
                this._stopAutoRefresh();
            }
        });

        this.el.search?.addEventListener('input', () => {
            clearTimeout(this._searchTimer);
            this._searchTimer = setTimeout(() => {
                this._search = this.el.search.value.trim().toLowerCase();
                this._selectedChange = null;
                this._render();
            }, 180);
        });

        this.el.refreshBtn?.addEventListener('click', () => this.refresh());
        this.el.locateGraph?.addEventListener('click', () => this._locateSelectedInGraph());
    },

    activate() {
        this._active = true;
        if (this.el?.view) this.el.view.hidden = false;
        if (this._traceContext) {
            if (this._traceSnapshots) {
                this._activateTraceSnapshots();
            } else {
                this._showHistoricalUnavailable();
            }
            return;
        }
        if (this._dirty) this.refresh();
        this._startAutoRefresh();
    },

    deactivate() {
        this._active = false;
        if (this.el?.view) this.el.view.hidden = true;
        this._stopAutoRefresh();
    },

    notifyDataChanged() {
        this._dirty = true;
        this._snapshotKey = '';
        if (this._active) this.refresh();
    },

    setTrace(trace) {
        this._traceContext = trace || null;
        this._mode = 'diff';
        this._expandedChangeGroups.clear();
        this._traceSnapshots = trace?.environment_snapshots || null;
        this._traceLegacy = false;
        if (!this._traceSnapshots && trace?.graph) {
            const legacy = this._legacyTraceSnapshots(trace);
            if (Object.keys(legacy).length) {
                this._traceSnapshots = legacy;
                this._traceLegacy = true;
            }
        }
        this._selectedChange = null;
        this._detail = null;
        if (this._traceSnapshots) {
            this._activateTraceSnapshots();
        } else if (this._active) {
            this._showHistoricalUnavailable();
        }
    },

    clearTrace() {
        this._traceContext = null;
        this._traceSnapshots = null;
        this._traceLegacy = false;
        this._expandedChangeGroups.clear();
        this._detail = null;
        this._selectedChange = null;
        this._snapshotKey = '';
        this._dirty = true;
        if (this._active) this.loadSuites();
    },

    _activateTraceSnapshots() {
        if (!this._traceSnapshots) {
            this._showHistoricalUnavailable();
            return;
        }
        this._stopAutoRefresh();
        const suites = Object.keys(this._traceSnapshots);
        if (!suites.length) {
            this._showHistoricalUnavailable();
            return;
        }
        this._suites = suites.map((suite) => {
            const snapshot = this._traceSnapshots[suite] || {};
            return {
                suite,
                label: window.AgentTraceAppCatalog?.appLabel(suite) || suite,
                color: (typeof GRAPH !== 'undefined'
                    && GRAPH.config?.appColors?.[suite])
                    || '#6e7b8a',
                change_total: snapshot.diff?.total || 0,
            };
        });
        if (!this._suite || !suites.includes(this._suite)) {
            const traceSuite = this._traceContext?.suite || this._traceContext?.app_name;
            this._suite = suites.includes(traceSuite) ? traceSuite : suites[0];
        }
        this._renderTraceSuite(this._suite);
    },

    _showHistoricalUnavailable() {
        this._suites = [];
        this._renderSuiteTabs();
        if (this.el?.summary) this.el.summary.innerHTML = '';
        if (this.el?.changeList) this.el.changeList.innerHTML = '';
        if (this.el?.diffBody) {
            this.el.diffBody.hidden = false;
            this.el.diffBody.innerHTML = '<div class="storage-empty">该历史记录未保存任务基线和执行后环境快照，无法回放环境变更。</div>';
        }
        if (this.el?.tree) this.el.tree.hidden = true;
        if (this.el?.breadcrumb) this.el.breadcrumb.textContent = '历史环境快照不可用';
        if (this.el?.status) this.el.status.textContent = '';
        if (this.el?.locateGraph) this.el.locateGraph.disabled = true;
    },

    _legacyTraceSnapshots(trace) {
        const nodes = Array.isArray(trace.graph?.nodes) ? trace.graph.nodes : [];
        const grouped = new Map();
        const kinds = { created: 'added', updated: 'changed', deleted: 'removed' };
        nodes.forEach((node) => {
            if (node.type !== 'DomainData') return;
            const kind = kinds[String(node.operation || '').toLowerCase()];
            if (!kind) return;
            const suite = ['workspace', 'banking', 'slack', 'travel'].includes(node.app)
                ? node.app
                : '';
            if (!suite) return;
            if (!grouped.has(suite)) grouped.set(suite, []);
            grouped.get(suite).push({
                path: `${suite}.${node.entity_type || 'entity'}.${node.id}`,
                kind,
                before: node.environment_delta?.before
                    ?? '旧版 trace 未保存变更前值',
                after: node.environment_delta?.after
                    ?? node.label
                    ?? node.id,
                entity: node.entity_type || '环境数据',
                field: node.id,
                sensitivity: {
                    level: node.flow_label?.confidentiality?.level || 'secret',
                    entity: node.entity_type || '',
                },
            });
        });

        const result = {};
        grouped.forEach((changes, suite) => {
            const counts = { added: 0, changed: 0, removed: 0 };
            changes.forEach(change => { counts[change.kind] += 1; });
            result[suite] = {
                initial: {},
                current: {},
                diff: {
                    changes,
                    counts,
                    total: changes.length,
                    truncated: false,
                    legacy_summary_only: true,
                },
                baseline_captured_at: '',
                captured_at: trace.timestamp || '',
                baseline_source: 'legacy_graph_summary',
            };
        });
        return result;
    },

    _renderTraceSuite(suite) {
        const snapshot = this._traceSnapshots?.[suite];
        if (!snapshot) {
            this._showHistoricalUnavailable();
            return;
        }
        this._suite = suite;
        this._detail = {
            suite,
            label: window.AgentTraceAppCatalog?.appLabel(suite) || suite,
            color: (typeof GRAPH !== 'undefined'
                && GRAPH.config?.appColors?.[suite])
                || '#6e7b8a',
            tools: [],
            initial: snapshot.initial || {},
            current: snapshot.current || {},
            diff: this._dedupeHistoricalDiff(
                snapshot.diff || { changes: [], counts: {}, total: 0 }
            ),
            baseline_captured_at: snapshot.baseline_captured_at || '',
            generated_at: snapshot.captured_at || this._traceContext?.timestamp || '',
            baseline_source: snapshot.baseline_source || 'task_start_after_fixtures',
            historical_trace_id: this._traceContext?.trace_id || '',
            legacy_summary_only: this._traceLegacy,
        };
        this._graphEvidence = this._collectGraphEvidence(suite);
        this._selectedChange = null;
        this._render();
    },

    _dedupeHistoricalDiff(diff) {
        const changes = Array.isArray(diff.changes) ? diff.changes : [];
        const aliases = [
            ['inbox.initial_emails[', 'inbox.emails.'],
            ['inbox.received[', 'inbox.emails.'],
            ['inbox.sent[', 'inbox.emails.'],
            ['inbox.drafts[', 'inbox.emails.'],
        ];
        const canonicalPath = (path) => {
            const value = String(path || '');
            for (const [alias, canonical] of aliases) {
                if (!value.startsWith(alias)) continue;
                return canonical + value.slice(alias.length).replace(']', '');
            }
            return value;
        };
        const groups = new Map();
        changes.forEach((change) => {
            const path = canonicalPath(change.path);
            const key = `${path}\u0000${change.kind}`;
            const existing = groups.get(key);
            if (!existing) {
                groups.set(key, {
                    ...change,
                    path,
                    source_paths: [change.path],
                });
                return;
            }
            existing.source_paths = [...new Set([
                ...(existing.source_paths || []),
                change.path,
            ])];
        });
        const normalized = [...groups.values()];
        const counts = { added: 0, changed: 0, removed: 0 };
        normalized.forEach((change) => {
            if (counts[change.kind] != null) counts[change.kind] += 1;
        });
        return {
            ...diff,
            changes: normalized,
            counts,
            total: normalized.length,
            raw_change_count: changes.length,
        };
    },

    refresh() {
        this._dirty = false;
        return this.loadSuites(true);
    },

    _startAutoRefresh() {
        this._stopAutoRefresh();
        if (!this.el?.autoRefresh?.checked) return;
        this._timer = setInterval(() => {
            if (this._active && this.el.autoRefresh?.checked) {
                this.loadSuites(true);
            }
        }, 5000);
    },

    _stopAutoRefresh() {
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
    },

    async loadSuites(silent = false) {
        if (this._traceSnapshots) {
            this._activateTraceSnapshots();
            return;
        }
        try {
            const data = await API.getStorageSuites();
            this._suites = Array.isArray(data.suites) ? data.suites : [];
            if (!this._suite || !this._suites.some(item => item.suite === this._suite)) {
                this._suite = this._suites[0]?.suite || null;
            }
            this._renderSuiteTabs();
            if (this._suite) await this.loadSuite(this._suite, silent);
        } catch (error) {
            if (this.el?.diffBody) {
                this.el.diffBody.innerHTML = '<div class="storage-empty">环境数据加载失败，请确认后端服务已启动。</div>';
            }
        }
    },

    async loadSuite(suite, silent = false) {
        if (!suite) return;
        if (this._traceSnapshots) {
            this._expandedChangeGroups.clear();
            this._renderTraceSuite(suite);
            return;
        }
        this._suite = suite;
        this._expandedChangeGroups.clear();
        try {
            const data = await API.getStorageSuite(suite, 'both');
            const key = JSON.stringify(data.current) + '|' + JSON.stringify(data.diff || {});
            if (silent && key === this._snapshotKey) {
                this._renderSuiteTabs();
                return;
            }
            this._snapshotKey = key;
            this._detail = data;
            this._graphEvidence = this._collectGraphEvidence(suite);
            this._selectedChange = null;
            this._render();
        } catch (error) {
            if (this.el?.diffBody) {
                this.el.diffBody.innerHTML = '<div class="storage-empty">该 APP 的环境快照加载失败。</div>';
            }
        }
    },

    openNode(node) {
        if (!node) return;
        if (node.type === 'AgentTool') {
            this.openTool(node);
            return;
        }
        const suite = String(node.suite || node.app || '');
        this._pendingNodeId = String(node.id || '');
        const tab = document.querySelector('.tab[data-tab="storage"]');
        if (tab && !tab.classList.contains('active')) tab.click();
        if (this._suites.some(item => item.suite === suite)) {
            this.loadSuite(suite);
        } else if (this._suite) {
            this.loadSuite(this._suite);
        }
    },

    openTool(tool) {
        if (!tool) return;
        const suite = String(tool.suite || tool.app || tool.target_app || '');
        this._pendingTool = String(tool.label || tool.tool_name || '');
        const tab = document.querySelector('.tab[data-tab="storage"]');
        if (tab && !tab.classList.contains('active')) tab.click();
        if (this._suites.some(item => item.suite === suite)) {
            this.loadSuite(suite);
        } else if (this._suite) {
            this.loadSuite(this._suite);
        }
    },

    _renderSuiteTabs() {
        if (!this.el.suiteTabs) return;
        this.el.suiteTabs.innerHTML = '';
        this._suites.forEach((item) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = `storage-suite-tab${item.suite === this._suite ? ' active' : ''}`;
            button.dataset.suite = item.suite;
            button.setAttribute('role', 'tab');
            button.setAttribute('aria-selected', item.suite === this._suite ? 'true' : 'false');

            const dot = document.createElement('span');
            dot.className = 'storage-suite-dot';
            dot.style.background = item.color || '#6e7b8a';
            const label = document.createElement('span');
            label.textContent = `${item.label} · ${item.suite}`;
            button.append(dot, label);
            if (item.change_total > 0) {
                const change = document.createElement('span');
                change.className = 'storage-suite-change';
                change.textContent = String(item.change_total);
                button.appendChild(change);
            }
            this.el.suiteTabs.appendChild(button);
        });
    },

    _changes() {
        return this._detail?.diff?.changes || [];
    },

    _filteredChanges() {
        const term = this._search;
        if (!term) return this._changes();
        return this._changes().filter((change) => {
            const text = [
                change.path,
                change.entity,
                change.field,
                change.sensitivity?.level,
                JSON.stringify(change.before),
                JSON.stringify(change.after),
            ].join(' ').toLowerCase();
            return text.includes(term);
        });
    },

    _render() {
        if (!this._detail) return;
        this._renderSuiteTabs();
        const changes = this._filteredChanges();
        if (
            !this._selectedChange
            || !changes.includes(this._selectedChange)
        ) {
            this._selectedChange = changes[0] || null;
        }
        if (this._pendingNodeId) {
            const matched = changes.find(change => (
                this._evidenceForChange(change)?.trace_node_id === this._pendingNodeId
            ));
            if (matched) this._selectedChange = matched;
            this._pendingNodeId = null;
        }
        if (this._pendingTool) {
            const matched = changes.find(change => (
                this._evidenceForChange(change)?.source_tool === this._pendingTool
            ));
            if (matched) this._selectedChange = matched;
            this._pendingTool = null;
        }

        this._renderSummary();
        this._renderChangeList(changes);
        this._renderBreadcrumb();
        this._syncModeControls();

        const isDiff = this._mode === 'diff';
        if (this.el.diffBody) this.el.diffBody.hidden = !isDiff;
        if (this.el.tree) this.el.tree.hidden = isDiff;
        if (isDiff) {
            this._renderDiff();
        } else {
            this._renderTree();
        }
        this._syncLocateButton();
    },

    _renderSummary() {
        if (!this.el.summary) return;
        const counts = this._detail?.diff?.counts || {};
        this.el.summary.innerHTML = '';
        [
            ['added', '新增', counts.added || 0],
            ['changed', '修改', counts.changed || 0],
            ['removed', '删除', counts.removed || 0],
        ].forEach(([kind, label, count]) => {
            const item = document.createElement('span');
            item.className = `storage-summary-item ${kind}`;
            item.textContent = `${label} ${count}`;
            this.el.summary.appendChild(item);
        });
    },

    _renderChangeList(changes) {
        if (!this.el.changeList) return;
        this.el.changeList.innerHTML = '';
        if (this.el.changeCount) this.el.changeCount.textContent = String(changes.length);
        if (!changes.length) {
            const empty = document.createElement('div');
            empty.className = 'storage-empty storage-empty-compact';
            empty.textContent = this._search ? '没有匹配的变更。' : '当前 APP 没有环境变更。';
            this.el.changeList.appendChild(empty);
            return;
        }

        const groups = new Map();
        changes.forEach((change) => {
            const entity = change.entity
                || change.sensitivity?.entity
                || String(change.path || '').split(/[.\[]/)[0]
                || '其他';
            if (!groups.has(entity)) groups.set(entity, []);
            groups.get(entity).push(change);
        });

        groups.forEach((entries, entity) => {
            const group = document.createElement('div');
            group.className = 'storage-change-group';
            const heading = document.createElement('div');
            heading.className = 'storage-change-group-title';
            heading.textContent = `${entity} · ${entries.length}`;
            group.appendChild(heading);

            const typeGroups = new Map();
            entries.forEach((change) => {
                const key = this._changeGroupKey(change, entity);
                if (!typeGroups.has(key)) typeGroups.set(key, []);
                typeGroups.get(key).push(change);
            });

            typeGroups.forEach((typeEntries, key) => {
                if (typeEntries.length === 1) {
                    group.appendChild(this._createChangeItem(typeEntries[0]));
                    return;
                }
                const expanded = this._expandedChangeGroups.has(key);
                const bundle = document.createElement('div');
                bundle.className = 'storage-change-bundle';
                const toggle = document.createElement('button');
                toggle.type = 'button';
                toggle.className = [
                    'storage-change-bundle-toggle',
                    `kind-${typeEntries[0].kind}`,
                ].join(' ');
                toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');

                const arrow = document.createElement('span');
                arrow.className = 'storage-change-bundle-arrow';
                arrow.textContent = expanded ? '▾' : '▸';
                const badge = document.createElement('span');
                badge.className = `storage-change-badge ${typeEntries[0].kind}`;
                badge.textContent = this._kindLabel(typeEntries[0].kind);
                const label = document.createElement('span');
                label.className = 'storage-change-bundle-label';
                const fields = [...new Set(
                    typeEntries
                        .map(change => String(change.field || '').trim())
                        .filter(Boolean)
                )];
                const labelText = fields.length <= 1
                    ? (fields[0] || entity)
                    : `${fields.length} 个字段`;
                label.textContent = `${labelText} · ${typeEntries.length} 项`;
                const levels = [...new Set(
                    typeEntries.map(change => (
                        change.sensitivity?.level || 'secret'
                    ))
                )];
                const meta = document.createElement('span');
                meta.className = 'storage-change-bundle-meta';
                meta.textContent = levels.length === 1
                    ? this._levelLabel(levels[0])
                    : `${levels.length} 种等级`;
                toggle.append(arrow, badge, label, meta);
                toggle.addEventListener('click', () => {
                    if (this._expandedChangeGroups.has(key)) {
                        this._expandedChangeGroups.delete(key);
                    } else {
                        this._expandedChangeGroups.add(key);
                    }
                    this._renderChangeList(this._filteredChanges());
                });
                bundle.appendChild(toggle);

                if (expanded) {
                    const children = document.createElement('div');
                    children.className = 'storage-change-bundle-items';
                    typeEntries.forEach((change) => {
                        children.appendChild(this._createChangeItem(change));
                    });
                    bundle.appendChild(children);
                }
                group.appendChild(bundle);
            });
            this.el.changeList.appendChild(group);
        });
    },

    _changeGroupKey(change, entity) {
        return [
            this._suite || change.suite || '',
            change.kind || '',
            entity || '',
        ].join('\u0000');
    },

    _createChangeItem(change) {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = [
            'storage-change-item',
            `kind-${change.kind}`,
            change === this._selectedChange ? 'active' : '',
        ].filter(Boolean).join(' ');
        item.setAttribute(
            'aria-pressed',
            change === this._selectedChange ? 'true' : 'false',
        );

        const head = document.createElement('span');
        head.className = 'storage-change-item-head';
        const kind = document.createElement('span');
        kind.className = `storage-change-badge ${change.kind}`;
        kind.textContent = this._kindLabel(change.kind);
        const path = document.createElement('span');
        path.className = 'storage-change-path';
        path.textContent = this._shortPath(change.path);
        head.append(kind, path);

        const meta = document.createElement('span');
        meta.className = 'storage-change-item-meta';
        const level = change.sensitivity?.level || 'secret';
        meta.textContent = `${this._levelLabel(level)}${change.field ? ` · ${change.field}` : ''}`;
        item.append(head, meta);
        item.title = change.path;
        item.addEventListener('click', () => this._selectChange(change));
        return item;
    },

    _renderBreadcrumb() {
        if (!this.el.breadcrumb || !this._detail) return;
        const mode = {
            diff: '字段差异',
            current: '当前快照',
            initial: '任务基线',
        }[this._mode] || '字段差异';
        const history = this._detail.historical_trace_id
            ? ` · 历史 ${this._detail.historical_trace_id}`
            : '';
        this.el.breadcrumb.textContent = `${this._detail.label} · ${this._detail.suite} · ${mode}${history}`;
        if (this.el.status) {
            const baseline = this._detail.baseline_captured_at
                ? `任务基线 ${this._detail.baseline_captured_at}`
                : '任务基线已捕获';
            const current = this._detail.generated_at
                ? `当前 ${this._detail.generated_at}`
                : '';
            this.el.status.textContent = [baseline, current].filter(Boolean).join(' · ');
            if (this._detail.legacy_summary_only) {
                this.el.status.textContent = '旧版历史记录 · 仅保留环境变更摘要';
            }
        }
    },

    _syncModeControls() {
        document.querySelectorAll('.storage-mode-btn').forEach((button) => {
            button.classList.toggle('active', button.dataset.mode === this._mode);
            button.disabled = Boolean(
                this._detail?.legacy_summary_only
                && button.dataset.mode !== 'diff'
            );
        });
        if (this.el.onlyChanges) {
            this.el.onlyChanges.disabled = this._mode === 'diff';
        }
    },

    _renderDiff() {
        if (!this.el.diffBody) return;
        this.el.diffBody.innerHTML = '';
        const change = this._selectedChange;
        if (!change) {
            this.el.diffBody.innerHTML = '<div class="storage-empty">该 APP 当前没有可展示的环境变更。</div>';
            return;
        }

        const card = document.createElement('section');
        card.className = `storage-diff-card kind-${change.kind}`;

        const head = document.createElement('header');
        head.className = 'storage-diff-head';
        const titleWrap = document.createElement('div');
        const kicker = document.createElement('div');
        kicker.className = 'storage-diff-kicker';
        kicker.textContent = change.entity || '环境数据';
        const title = document.createElement('h3');
        title.textContent = change.path || change.field || '环境变更';
        const subtitle = document.createElement('div');
        subtitle.className = 'storage-diff-path';
        subtitle.textContent = `${this._kindLabel(change.kind)}${change.field ? ` · ${change.field}` : ''}`;
        titleWrap.append(kicker, title, subtitle);
        const badge = document.createElement('span');
        badge.className = `storage-change-badge ${change.kind}`;
        badge.textContent = this._kindLabel(change.kind);
        head.append(titleWrap, badge);

        const meta = document.createElement('div');
        meta.className = 'storage-diff-meta';
        const sensitivity = document.createElement('span');
        const level = change.sensitivity?.level || 'secret';
        sensitivity.className = `storage-level-badge level-${level}`;
        sensitivity.textContent = `敏感等级 · ${this._levelLabel(level)}`;
        meta.appendChild(sensitivity);
        const evidence = this._evidenceForChange(change);
        if (evidence?.source_tool) {
            const tool = document.createElement('span');
            tool.className = 'storage-diff-chip';
            tool.textContent = `来源工具 · ${evidence.source_tool}`;
            meta.appendChild(tool);
        }

        const grid = document.createElement('div');
        grid.className = 'storage-diff-grid';
        [
            ['变更前', change.before, 'before'],
            ['变更后', change.after, 'after'],
        ].forEach(([label, value, side]) => {
            const block = document.createElement('section');
            block.className = `storage-diff-value ${side}`;
            const labelEl = document.createElement('div');
            labelEl.className = 'storage-diff-value-label';
            labelEl.textContent = label;
            const pre = document.createElement('pre');
            pre.textContent = value == null ? '不存在' : this._formatValue(value);
            block.append(labelEl, pre);
            grid.appendChild(block);
        });

        const source = document.createElement('section');
        source.className = 'storage-source-chain';
        const sourceTitle = document.createElement('div');
        sourceTitle.className = 'storage-source-chain-title';
        sourceTitle.textContent = '来源与审计链';
        source.appendChild(sourceTitle);
        [evidence?.source_tool && `工具 ${evidence.source_tool}`,
            evidence?.trace_node_id && `图谱节点 ${evidence.trace_node_id}`,
            evidence?.source_level && `数据等级 ${this._levelLabel(evidence.source_level)}`,
        ].filter(Boolean).forEach((text) => {
            const line = document.createElement('div');
            line.className = 'storage-source-chain-item';
            line.textContent = text;
            source.appendChild(line);
        });
        if (source.childElementCount === 1) {
            const note = document.createElement('div');
            note.className = 'storage-source-chain-empty';
            note.textContent = '当前 trace 中没有找到对应的环境变更节点；仍可在完整快照中审计原始字段。';
            source.appendChild(note);
        }

        card.append(head, meta, grid, source);
        this.el.diffBody.appendChild(card);
    },

    _selectChange(change) {
        this._selectedChange = change;
        if (this._mode === 'diff') {
            this._render();
            return;
        }
        this._renderChangeList(this._filteredChanges());
        this._syncLocateButton();
        const node = this.el.tree?.querySelector(`[data-path="${CSS.escape(change.path)}"]`);
        if (node?.scrollIntoView) node.scrollIntoView({ block: 'center' });
    },

    _locateSelectedInGraph() {
        const evidence = this._evidenceForChange(this._selectedChange);
        if (!evidence?.trace_node_id) return;
        const monitorTab = document.querySelector('.tab[data-tab="monitor"]');
        if (monitorTab) monitorTab.click();
        requestAnimationFrame(() => {
            if (typeof GRAPH !== 'undefined' && GRAPH.flashNode) {
                GRAPH.flashNode(evidence.trace_node_id);
            }
        });
    },

    _syncLocateButton() {
        if (!this.el.locateGraph) return;
        const evidence = this._evidenceForChange(this._selectedChange);
        this.el.locateGraph.disabled = !evidence?.trace_node_id;
        this.el.locateGraph.title = evidence?.trace_node_id
            ? '切换到监控视图并定位对应环境变更节点'
            : '当前 trace 中没有对应的环境变更节点';
    },

    _collectGraphEvidence(suite) {
        if (typeof GRAPH === 'undefined' || !Array.isArray(GRAPH.nodes)) return [];
        const nodes = GRAPH.nodes;
        const links = Array.isArray(GRAPH.links) ? GRAPH.links : [];
        const toolByOutput = new Map();
        links.forEach((link) => {
            if (link.relation !== 'produces') return;
            const sourceId = link.source?.id || link.source;
            const targetId = link.target?.id || link.target;
            const tool = nodes.find(node => node.id === sourceId && node.type === 'AgentTool');
            if (tool && targetId) toolByOutput.set(String(targetId), tool);
        });

        return nodes
            .filter(node => (
                node.type === 'DomainData'
                && ['created', 'updated', 'deleted'].includes(String(node.operation || '').toLowerCase())
                && (!suite || [node.suite, node.app].includes(suite))
            ))
            .map((node) => {
                const tool = toolByOutput.get(String(node.id));
                return {
                    trace_node_id: String(node.id),
                    entity: String(node.entity_type || ''),
                    source_tool: String(tool?.label || tool?.id || ''),
                    source_level: String(node.flow_label?.confidentiality?.level || ''),
                };
            });
    },

    _evidenceForChange(change) {
        if (!change || !this._graphEvidence.length) return null;
        const entity = this._normalizeToken(
            change.entity || change.sensitivity?.entity || change.path,
        );
        const exact = this._graphEvidence.find(item => (
            this._normalizeToken(item.entity) === entity
        ));
        if (exact) return exact;
        return this._graphEvidence.find(item => (
            entity.includes(this._normalizeToken(item.entity))
            || this._normalizeToken(item.entity).includes(entity)
        )) || null;
    },

    _normalizeToken(value) {
        return String(value || '')
            .toLowerCase()
            .replace(/\[\d+\]/g, '')
            .replace(/[^a-z0-9]+/g, '_')
            .replace(/^_+|_+$/g, '');
    },

    _renderTree() {
        if (!this.el.tree || !this._detail) return;
        const snapshot = this._mode === 'initial'
            ? this._detail.initial
            : this._detail.current;
        if (!snapshot) {
            this.el.tree.innerHTML = '<div class="storage-empty">没有可展示的快照数据。</div>';
            return;
        }

        const changes = new Map(
            this._changes().map(change => [change.path, change]),
        );
        const selectedPath = this._selectedChange?.path || '';
        this.el.tree.innerHTML = '';
        const children = document.createElement('div');
        Object.keys(snapshot).forEach((key) => {
            const node = this._renderNode(
                key,
                snapshot[key],
                key,
                0,
                changes,
                selectedPath,
            );
            if (node) children.appendChild(node);
        });
        if (!children.childElementCount) {
            this.el.tree.innerHTML = '<div class="storage-empty">没有符合条件的数据。</div>';
        } else {
            this.el.tree.appendChild(children);
        }
    },

    _matchesSearch(path, value) {
        if (!this._search) return true;
        if (path.toLowerCase().includes(this._search)) return true;
        try {
            return JSON.stringify(value).toLowerCase().includes(this._search);
        } catch (error) {
            return false;
        }
    },

    _renderNode(key, value, path, depth, changes, selectedPath) {
        const change = changes.get(path);
        const kind = change?.kind || this._kindForPath(path, changes);
        if (this._onlyChanges && !kind) return null;
        if (!this._matchesSearch(path, value)) return null;
        if (value !== null && typeof value === 'object') {
            return this._renderContainer(
                key,
                value,
                path,
                depth,
                kind,
                changes,
                selectedPath,
            );
        }
        return this._renderLeaf(key, value, path, kind);
    },

    _renderContainer(key, value, path, depth, kind, changes, selectedPath) {
        const isArray = Array.isArray(value);
        const idKey = isArray ? this._listIdKey(value) : null;
        const entries = isArray
            ? value.map((item, index) => {
                const itemKey = idKey && item?.[idKey] !== undefined ? item[idKey] : index;
                return [`[${itemKey}]`, item, `${path}[${itemKey}]`];
            })
            : Object.keys(value).map(childKey => [
                childKey,
                value[childKey],
                `${path}.${childKey}`,
            ]);

        const details = document.createElement('details');
        details.className = `storage-node${kind ? ` kind-${kind}` : ''}`;
        details.dataset.path = path;
        details.open = depth < 1
            || Boolean(selectedPath && selectedPath.startsWith(path))
            || (kind === 'changed' && depth < 3);

        const summary = document.createElement('summary');
        const keyEl = document.createElement('span');
        keyEl.className = 'storage-key';
        keyEl.textContent = key;
        const colon = document.createElement('span');
        colon.className = 'storage-colon';
        colon.textContent = ':';
        const typeEl = document.createElement('span');
        typeEl.className = 'storage-type';
        typeEl.textContent = isArray ? `array(${value.length})` : `object(${entries.length})`;
        summary.append(keyEl, colon, typeEl);
        if (kind) summary.appendChild(this._changeBadge(kind));
        details.appendChild(summary);

        const children = document.createElement('div');
        children.className = 'storage-children';
        entries.forEach(([childKey, childValue, childPath]) => {
            const node = this._renderNode(
                childKey,
                childValue,
                childPath,
                depth + 1,
                changes,
                selectedPath,
            );
            if (node) children.appendChild(node);
        });
        if (children.childElementCount) details.appendChild(children);
        return details;
    },

    _renderLeaf(key, value, path, kind) {
        const row = document.createElement('div');
        row.className = `storage-row${kind ? ` kind-${kind}` : ''}`;
        row.dataset.path = path;
        const keyEl = document.createElement('span');
        keyEl.className = 'storage-key';
        keyEl.textContent = key;
        const colon = document.createElement('span');
        colon.className = 'storage-colon';
        colon.textContent = ':';
        const valueEl = document.createElement('span');
        valueEl.className = `storage-value type-${value === null ? 'null' : typeof value}`;
        valueEl.textContent = value === null ? 'null' : String(value);
        row.append(keyEl, colon, valueEl);
        if (kind) row.appendChild(this._changeBadge(kind));
        return row;
    },

    _changeBadge(kind) {
        const badge = document.createElement('span');
        badge.className = `storage-change-badge ${kind}`;
        badge.textContent = this._kindLabel(kind);
        return badge;
    },

    _kindForPath(path, changes) {
        for (const changePath of changes.keys()) {
            if (changePath.startsWith(`${path}.`) || changePath.startsWith(`${path}[`)) {
                return 'changed';
            }
        }
        return null;
    },

    _listIdKey(items) {
        const keys = ['id_', 'id', 'filename', 'subject', 'title', 'name'];
        const objects = items.filter(item => item && typeof item === 'object');
        if (!objects.length) return null;
        return keys.find(key => objects.every(item => key in item)) || null;
    },

    _formatValue(value) {
        if (typeof value === 'string') return value;
        try {
            return JSON.stringify(value, null, 2);
        } catch (error) {
            return String(value);
        }
    },

    _shortPath(path) {
        return String(path || '');
    },

    _kindLabel(kind) {
        return {
            added: '新增',
            changed: '修改',
            removed: '删除',
        }[kind] || kind || '';
    },

    _levelLabel(level) {
        return {
            public: '公开',
            internal: '内部',
            confidential: '私密',
            secret: '机密',
        }[String(level || '').toLowerCase()] || level || '未标注';
    },
};
