/**
 * 存储视图 - 从“环境数据/存储”角度观察四个 suite。
 *
 * 展示内容：
 * - 每个 suite 的初始快照（原版 YAML）与当前快照（agent 执行后的内存状态）
 * - 相对初始状态的变更（added / removed / changed）
 * - 支持搜索、仅显示变化、自动刷新与变更详情
 */

const STORAGE_VIEW = {
    _initialized: false,
    _active: false,
    _dirty: true,
    _suites: [],
    _suite: null,
    _mode: 'current',
    _onlyChanges: false,
    _search: '',
    _timer: null,
    _detail: null,
    _selectedChange: null,
    _snapshotKey: '',
    _searchTimer: null,

    init() {
        if (this._initialized) return;
        this._initialized = true;

        this.el = {
            view: document.getElementById('storageView'),
            suiteTabs: document.getElementById('storageSuiteTabs'),
            suiteList: document.getElementById('storageSuiteList'),
            changeList: document.getElementById('storageChangeList'),
            changeCount: document.getElementById('storageChangeCount'),
            tree: document.getElementById('storageTree'),
            breadcrumb: document.getElementById('storageBreadcrumb'),
            status: document.getElementById('storageStatus'),
            search: document.getElementById('storageSearch'),
            onlyChanges: document.getElementById('storageOnlyChanges'),
            autoRefresh: document.getElementById('storageAutoRefresh'),
            refreshBtn: document.getElementById('storageRefreshBtn'),
            detail: document.getElementById('storageDetail'),
            detailTitle: document.getElementById('storageDetailTitle'),
            detailBody: document.getElementById('storageDetailBody'),
            detailClose: document.getElementById('storageDetailClose'),
        };

        this._bindEvents();
        this.loadSuites();
    },

    _bindEvents() {
        if (this.el.suiteTabs) {
            this.el.suiteTabs.addEventListener('click', (ev) => {
                const btn = ev.target.closest('.storage-suite-tab');
                if (!btn) return;
                this.loadSuite(btn.dataset.suite);
            });
        }

        if (this.el.suiteList) {
            this.el.suiteList.addEventListener('click', (ev) => {
                const item = ev.target.closest('.storage-suite-item');
                if (!item) return;
                this.loadSuite(item.dataset.suite);
            });
        }

        const modeGroup = document.getElementById('storageMode');
        if (modeGroup) {
            modeGroup.addEventListener('click', (ev) => {
                const btn = ev.target.closest('.storage-mode-btn');
                if (!btn) return;
                this._mode = btn.dataset.mode || 'current';
                modeGroup.querySelectorAll('.storage-mode-btn').forEach((item) => {
                    item.classList.toggle('active', item === btn);
                });
                this._selectedChange = null;
                this._render();
            });
        }

        if (this.el.onlyChanges) {
            this.el.onlyChanges.addEventListener('change', () => {
                this._onlyChanges = this.el.onlyChanges.checked;
                this._render();
            });
        }

        if (this.el.search) {
            this.el.search.addEventListener('input', () => {
                clearTimeout(this._searchTimer);
                this._searchTimer = setTimeout(() => {
                    this._search = this.el.search.value.trim().toLowerCase();
                    this._render();
                }, 180);
            });
        }

        if (this.el.refreshBtn) {
            this.el.refreshBtn.addEventListener('click', () => this.refresh());
        }

        if (this.el.detailClose) {
            this.el.detailClose.addEventListener('click', () => {
                this._selectedChange = null;
                if (this.el.detail) this.el.detail.hidden = true;
            });
        }
    },

    activate() {
        this._active = true;
        if (this.el && this.el.view) this.el.view.hidden = false;
        if (this._dirty) this.refresh();
        this._startAutoRefresh();
    },

    deactivate() {
        this._active = false;
        if (this.el && this.el.view) this.el.view.hidden = true;
        this._stopAutoRefresh();
    },

    notifyDataChanged() {
        this._dirty = true;
        this._snapshotKey = '';
        if (this._active) this.refresh();
    },

    refresh() {
        this._dirty = false;
        return this.loadSuites(true);
    },

    _startAutoRefresh() {
        this._stopAutoRefresh();
        if (!this.el || !this.el.autoRefresh || !this.el.autoRefresh.checked) return;
        this._timer = setInterval(() => {
            if (!this._active) return;
            if (this.el.autoRefresh && !this.el.autoRefresh.checked) return;
            this.loadSuites(true);
        }, 5000);
    },

    _stopAutoRefresh() {
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
    },

    async loadSuites(silent = false) {
        try {
            const data = await API.getStorageSuites();
            this._suites = data.suites || [];
            if (!this._suite || !this._suites.some(item => item.suite === this._suite)) {
                this._suite = this._suites.length > 0 ? this._suites[0].suite : null;
            }
            this._renderSuiteTabs();
            this._renderSuiteList();
            if (this._suite) {
                await this.loadSuite(this._suite, silent);
            }
        } catch (err) {
            if (this.el && this.el.tree) {
                this.el.tree.innerHTML = '<div class="storage-empty">存储数据加载失败，请确认后端服务已启动。</div>';
            }
        }
    },

    async loadSuite(suite, silent = false) {
        this._suite = suite;
        try {
            const data = await API.getStorageSuite(suite, 'both');
            const key = JSON.stringify(data.current) + '|' + JSON.stringify((data.diff || {}).total);
            if (silent && key === this._snapshotKey) {
                this._renderSuiteTabs();
                this._renderSuiteList();
                return;
            }
            this._snapshotKey = key;
            this._detail = data;
            this._selectedChange = null;
            if (this.el.detail) this.el.detail.hidden = true;
            this._render();
        } catch (err) {
            if (this.el && this.el.tree) {
                this.el.tree.innerHTML = '<div class="storage-empty">该 suite 的存储快照加载失败。</div>';
            }
        }
    },

    _renderSuiteTabs() {
        if (!this.el.suiteTabs) return;
        this.el.suiteTabs.innerHTML = '';
        this._suites.forEach((item) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'storage-suite-tab' + (item.suite === this._suite ? ' active' : '');
            btn.dataset.suite = item.suite;
            btn.setAttribute('role', 'tab');
            btn.setAttribute('aria-selected', item.suite === this._suite ? 'true' : 'false');

            const dot = document.createElement('span');
            dot.className = 'storage-suite-dot';
            dot.style.background = item.color || '#6e7b8a';

            const label = document.createElement('span');
            label.textContent = `${item.label} (${item.suite})`;

            btn.append(dot, label);
            if (item.change_total > 0) {
                const change = document.createElement('span');
                change.className = 'storage-suite-change';
                change.textContent = `+${item.change_total}`;
                btn.appendChild(change);
            }
            this.el.suiteTabs.appendChild(btn);
        });
    },

    _renderSuiteList() {
        if (!this.el.suiteList) return;
        this.el.suiteList.innerHTML = '';
        this._suites.forEach((item) => {
            const card = document.createElement('div');
            card.className = 'storage-suite-item' + (item.suite === this._suite ? ' active' : '');
            card.dataset.suite = item.suite;

            const head = document.createElement('div');
            head.className = 'storage-suite-item-head';
            const dot = document.createElement('span');
            dot.className = 'storage-suite-dot';
            dot.style.background = item.color || '#6e7b8a';
            const name = document.createElement('span');
            name.textContent = `${item.label} (${item.suite})`;
            head.append(dot, name);

            const meta = document.createElement('div');
            meta.className = 'storage-suite-item-meta';
            const summary = (item.summary || [])
                .map(entry => `${entry.key}:${entry.count}`)
                .join(' · ');
            meta.textContent = `${item.tool_count} tools | ${summary} | 变更 ${item.change_total}`;

            card.append(head, meta);
            this.el.suiteList.appendChild(card);
        });
    },

    _changes() {
        return (this._detail && this._detail.diff && this._detail.diff.changes) || [];
    },

    _changeMap() {
        const map = new Map();
        this._changes().forEach((change) => map.set(change.path, change));
        return map;
    },

    _kindForPath(path, changes) {
        const exact = changes.get(path);
        if (exact) return exact.kind;
        for (const changePath of changes.keys()) {
            if (changePath.startsWith(`${path}.`) || changePath.startsWith(`${path}[`)) {
                return 'changed';
            }
        }
        return null;
    },

    _render() {
        if (!this._detail) return;
        this._renderChangeList();
        this._renderBreadcrumb();
        this._renderTree();
    },

    _renderBreadcrumb() {
        if (!this.el.breadcrumb || !this._detail) return;
        const modeLabel = this._mode === 'current' ? '当前状态' : '初始状态';
        const changeTotal = (this._detail.diff || {}).total || 0;
        this.el.breadcrumb.textContent = `${this._detail.label} (${this._detail.suite}) · ${modeLabel} · 变更 ${changeTotal}`;
        if (this.el.status) {
            this.el.status.textContent = `生成时间 ${this._detail.generated_at || ''}`;
        }
    },

    _renderChangeList() {
        if (!this.el.changeList) return;
        this.el.changeList.innerHTML = '';
        const changes = this._changes();
        if (this.el.changeCount) this.el.changeCount.textContent = String(changes.length);

        if (changes.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'hint';
            empty.textContent = '当前状态与初始状态一致。';
            this.el.changeList.appendChild(empty);
            return;
        }

        changes.forEach((change) => {
            const item = document.createElement('div');
            item.className = `storage-change-item kind-${change.kind}`;
            const kind = document.createElement('span');
            kind.className = 'storage-change-kind';
            kind.textContent = change.kind;
            const path = document.createElement('span');
            path.className = 'storage-change-path';
            path.textContent = change.path;
            item.append(kind, path);
            item.addEventListener('click', () => this._selectChange(change));
            this.el.changeList.appendChild(item);
        });
    },

    _selectChange(change) {
        this._selectedChange = change;
        this._renderTree();
        this._showDetail(change);
        const node = this.el.tree && this.el.tree.querySelector(`[data-path="${CSS.escape(change.path)}"]`);
        if (node && node.scrollIntoView) node.scrollIntoView({ block: 'center' });
    },

    _showDetail(change) {
        if (!this.el.detail || !this.el.detailBody) return;
        this.el.detail.hidden = false;
        if (this.el.detailTitle) this.el.detailTitle.textContent = `变更 · ${change.kind}`;
        this.el.detailBody.innerHTML = '';

        const blocks = [
            ['路径', change.path],
            ['变更前', change.before],
            ['变更后', change.after],
        ];
        blocks.forEach(([label, value]) => {
            const block = document.createElement('div');
            block.className = 'storage-detail-block';
            const title = document.createElement('span');
            title.className = 'storage-detail-label';
            title.textContent = label;
            const pre = document.createElement('pre');
            pre.className = 'storage-detail-code';
            pre.textContent = typeof value === 'string'
                ? value
                : JSON.stringify(value, null, 2);
            block.append(title, pre);
            this.el.detailBody.appendChild(block);
        });
    },

    _renderTree() {
        if (!this.el.tree || !this._detail) return;
        const snapshot = this._mode === 'initial' ? this._detail.initial : this._detail.current;
        if (!snapshot) {
            this.el.tree.innerHTML = '<div class="storage-empty">没有可展示的快照数据。</div>';
            return;
        }

        const changes = this._changeMap();
        const selectedPath = this._selectedChange ? this._selectedChange.path : '';
        this.el.tree.innerHTML = '';

        const children = document.createElement('div');
        Object.keys(snapshot).forEach((key) => {
            const node = this._renderNode(key, snapshot[key], key, 0, changes, selectedPath);
            if (node) children.appendChild(node);
        });

        if (children.childElementCount === 0) {
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
        } catch (err) {
            return false;
        }
    },

    _renderNode(key, value, path, depth, changes, selectedPath) {
        const kind = this._kindForPath(path, changes);
        if (this._onlyChanges && !kind) return null;
        if (!this._matchesSearch(path, value)) return null;

        if (value !== null && typeof value === 'object') {
            return this._renderContainer(key, value, path, depth, kind, changes, selectedPath);
        }
        return this._renderLeaf(key, value, path, kind);
    },

    _renderContainer(key, value, path, depth, kind, changes, selectedPath) {
        const isArray = Array.isArray(value);
        const idKey = isArray ? this._listIdKey(value) : null;
        const entries = isArray
            ? value.map((item, index) => {
                const itemKey = idKey && item && item[idKey] !== undefined ? item[idKey] : index;
                return [`[${itemKey}]`, item, `${path}[${itemKey}]`];
            })
            : Object.keys(value).map((childKey) => [childKey, value[childKey], `${path}.${childKey}`]);

        const details = document.createElement('details');
        details.className = 'storage-node' + (kind ? ` kind-${kind}` : '');
        details.dataset.path = path;
        details.open = depth < 1
            || (selectedPath && selectedPath.startsWith(path))
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
            const node = this._renderNode(childKey, childValue, childPath, depth + 1, changes, selectedPath);
            if (node) children.appendChild(node);
        });
        if (children.childElementCount > 0) {
            details.appendChild(children);
        }
        return details;
    },

    _renderLeaf(key, value, path, kind) {
        const row = document.createElement('div');
        row.className = 'storage-row' + (kind ? ` kind-${kind}` : '');
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
        badge.textContent = kind === 'added' ? '新增' : kind === 'removed' ? '删除' : '变更';
        return badge;
    },

    _listIdKey(items) {
        const keys = ['id_', 'id', 'filename', 'subject', 'title', 'name'];
        const dictItems = items.filter(item => item && typeof item === 'object');
        if (dictItems.length === 0) return null;
        return keys.find(key => dictItems.every(item => key in item)) || null;
    },
};
