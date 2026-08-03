/**
 * 主入口模块 - AgentDojo 数据流追踪可视化平台
 * 
 * 初始化所有模块，协调数据加载和页面交互。
 * 
 * 增强功能：
 * - 统一状态管理（Store）
 * - 事件发布/订阅模式
 * - 优化轮询逻辑（增量更新检测）
 * - 加载状态管理
 * - 错误边界处理
 */

// ============================================================
// 全局状态管理
// ============================================================
const Store = {
    _state: {
        loading: true,
        error: null,
        lastNodeCount: 0,
        lastEdgeCount: 0,
        isPolling: false,
    },
    
    _listeners: {},
    
    get(key) {
        return this._state[key];
    },
    
    set(key, value) {
        const old = this._state[key];
        this._state[key] = value;
        this._emit(key, value, old);
    },
    
    on(event, callback) {
        if (!this._listeners[event]) {
            this._listeners[event] = [];
        }
        this._listeners[event].push(callback);
    },
    
    _emit(event, newVal, oldVal) {
        (this._listeners[event] || []).forEach(cb => cb(newVal, oldVal));
    },
    
    // 全局事件总线
    publish(event, data) {
        (this._listeners[event] || []).forEach(cb => cb(data));
    },
    
    subscribe(event, callback) {
        this.on(event, callback);
    }
};

// ============================================================
// 应用主入口
// ============================================================
const APP = {
    /**
     * 应用初始化
     */
    async init() {
        console.log('🛡️ AgentDojo 数据流追踪可视化平台启动中...');
        
        // 显示加载状态
        this._showLoading();
        
        try {
            // 初始化各模块
            GRAPH.init();
            TIMELINE.init();
            RISK_PANEL.init();
            STATUS_PANEL.init();
            TRACE_PANEL.init();
            await CONSOLE.init();

            
            // 绑定导航标签切换
            this._initTabs();
            
            // 绑定弹窗关闭
            this._initModal();
            
            // 绑定重置按钮
            this._initResetButton();
            
            // 初始化浮动面板交互
            this._initFloatPanel();
            
            // 加载数据
            await GRAPH.loadData();
            
            // 更新状态
            Store.set('loading', false);
            Store.set('lastNodeCount', GRAPH.nodes.length);
            Store.set('lastEdgeCount', GRAPH.links.length);
            
            // 隐藏加载状态
            this._hideLoading();
            
            // 启动定时刷新（每 5 秒检查新数据）
            this._startPolling();
            
            console.log('✅ 可视化平台启动完成');
        } catch (err) {
            console.error('❌ 应用启动失败:', err);
            this._showError('应用启动失败，请检查后端服务是否正常运行。');
            Store.set('loading', false);
            Store.set('error', err.message);
        }
    },

    /**
     * 显示加载状态
     */
    _showLoading() {
        const container = document.getElementById('graph-container');
        if (!container) return;
        
        const loadingEl = document.createElement('div');
        loadingEl.className = 'loading-overlay';
        loadingEl.id = 'loadingOverlay';
        loadingEl.innerHTML = `
            <div class="loading-spinner"></div>
            <div class="loading-text">正在加载图谱数据...</div>
        `;
        container.appendChild(loadingEl);
    },

    /**
     * 隐藏加载状态
     */
    _hideLoading() {
        const loadingEl = document.getElementById('loadingOverlay');
        if (loadingEl) {
            loadingEl.style.opacity = '0';
            setTimeout(() => loadingEl.remove(), 500);
        }
    },

    /**
     * 显示错误信息
     */
    _showError(message) {
        const container = document.getElementById('graph-container');
        if (!container) return;
        
        const errorEl = document.createElement('div');
        errorEl.className = 'error-overlay';
        errorEl.innerHTML = `
            <div class="error-icon">⚠️</div>
            <div class="error-text">${message}</div>
            <button class="error-retry" onclick="APP.init()">🔄 重试</button>
        `;
        container.appendChild(errorEl);
    },

    /**
     * 初始化导航标签切换
     */
    _initTabs() {
        const tabs = document.querySelectorAll('.tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // 切换标签激活状态
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                // 切换视图模式
                const tabName = tab.dataset.tab;
                this._switchView(tabName);
            });
        });
    },

    /**
     * 切换视图模式
     */
    _switchView(tabName) {
        const graphPanel = document.querySelector('.graph-panel');
        const sidePanel = document.querySelector('.side-panel');
        const timelinePanel = document.querySelector('.timeline-panel');
        
        switch (tabName) {
            case 'monitor':
                // 实时监控：显示所有面板
                graphPanel.style.display = 'flex';
                sidePanel.style.display = 'flex';
                timelinePanel.style.display = 'flex';
                document.getElementById('statusText').textContent = '实时';
                document.querySelector('.status-dot').className = 'status-dot live';
                break;
                
            case 'history':
                // 历史回放：放大拓扑图，隐藏风险卡片
                graphPanel.style.display = 'flex';
                sidePanel.style.display = 'flex';
                timelinePanel.style.display = 'flex';
                document.getElementById('statusText').textContent = '回放';
                this._loadHistoryList();
                document.querySelector('.status-dot').className = 'status-dot';
                break;
                
            case 'audit':
                // 风险审计：放大风险卡片，缩小拓扑图
                graphPanel.style.display = 'flex';
                sidePanel.style.display = 'flex';
                timelinePanel.style.display = 'none';
                document.getElementById('statusText').textContent = '审计';
                document.querySelector('.status-dot').className = 'status-dot';
                // 滚动到风险卡片区域
                document.querySelector('.risk-card-panel').scrollIntoView({ behavior: 'smooth' });
                break;
        }
        
        // 触发窗口大小变化事件，让 D3 重新计算布局
        window.dispatchEvent(new Event('resize'));
        var hp = document.getElementById('historyListPanel'); if (tabName!=='history'&&hp)hp.style.display='none';
        if (tabName === 'history') this._loadHistoryList();
        if (tabName === 'audit') this._renderAuditExport();
    },

    /**
     * 初始化节点详情弹窗
     */
    async _loadHistoryList() {
        var data = await API.getTraces();
        var panel = document.getElementById('historyListPanel');
        if (!panel) {
            panel = document.createElement('div'); panel.id = 'historyListPanel';
            panel.style.cssText = 'position:absolute;top:50px;left:16px;right:16px;bottom:16px;overflow-y:auto;z-index:10;background:var(--bg-secondary);border-radius:8px;padding:16px;display:none';
            document.querySelector('.graph-panel').style.position = 'relative';
            document.querySelector('.graph-panel').appendChild(panel);
        }
        if (!data||!data.traces||!data.traces.length) {
            panel.innerHTML = '<div style=\"color:var(--text-muted);padding:20px;text-align:center\">暂无历史记录，执行指令后出现</div>';
        } else {
                        var h='<h4>历史记录('+data.total+')</h4>';
            for (var i=0;i<data.traces.length;i++) {
                var t=data.traces[i],ic=t.blocked?'🚫':'✅';
                h+='<div style="cursor:pointer;padding:8px;margin:4px 0;background:var(--bg-card);border-radius:4px;border-left:3px solid '+(t.blocked?'var(--accent-red)':'var(--accent-green)')+'" onclick="APP._replayTrace(\''+t.trace_id+'\')">'+ic+' '+(t.prompt||'')+'<br><small style="color:var(--text-secondary)">'+t.timestamp+' | '+t.app_name+' | '+t.total_steps+'步'+(t.blocked?' | 阻断':'')+'</small></div>';
            }
            panel.innerHTML=h;
        }
        panel.style.display='block';
    },
    async _replayTrace(tid) {
        var d=await API.getTrace(tid); if(!d){alert('加载失败');return;}
        var p=document.getElementById('historyListPanel'); if(p)p.style.display='none';
        if(d.graph&&d.graph.nodes&&d.graph.nodes.length){GRAPH.setData(d.graph.nodes,d.graph.links);GRAPH.render();}
        else if(d.graph&&d.graph.nodes){GRAPH.setData([],[]);GRAPH.render();}
        else {this._showHistoryHint('该历史记录未保存拓扑快照（旧版记录），仅显示流转步骤');GRAPH.setData([],[]);GRAPH.render();}
        if(d.events&&d.events.length){TIMELINE.setEvents(d.events);}else{TIMELINE.clear();}
        if(d.steps&&d.steps.length)TRACE_PANEL._renderTrace(d);
        var t=document.querySelector('.navbar-tabs .tab[data-tab="monitor"]'); if(t)t.click();
    },
    _showHistoryHint(msg) {
        var g=document.querySelector('.graph-panel'); if(!g)return;
        var el=document.createElement('div');
        el.style.cssText='position:absolute;top:12px;left:50%;transform:translateX(-50%);z-index:30;background:var(--bg-card);color:var(--text-secondary);padding:8px 16px;border-radius:6px;font-size:12px;border:1px solid var(--accent-blue)';
        el.textContent=msg;
        g.appendChild(el);
        setTimeout(function(){el.remove()},4000);
    },
    _renderAuditExport() {
        var p=document.getElementById('auditExportPanel');
        if(!p){
            p=document.createElement('div');p.id='auditExportPanel';
            p.style.cssText='margin:12px 0;padding:12px;background:var(--bg-card);border-radius:8px;text-align:center';
            var r=document.querySelector('.risk-card-panel'); if(r)r.insertBefore(p,r.firstChild);
        }
        p.innerHTML='<button onclick="API.getTraces().then(function(d){var t=d.traces&&d.traces[0];if(t)API.getTrace(t.trace_id).then(function(f){var b=new Blob([JSON.stringify(f,null,2)]);var a=document.createElement(\'a\');a.href=URL.createObjectURL(b);a.download=t.trace_id+\'.json\';a.click()})})" style="background:var(--accent-blue);color:#fff;border:none;padding:6px 16px;border-radius:6px;cursor:pointer;margin-right:8px">导出最新 Trace</button><span style="font-size:12px;color:var(--text-secondary)">审计模式</span>';
    },

    _initModal() {
        const modal = document.getElementById('nodeModal');
        const closeBtn = modal.querySelector('.modal-close');
        
        closeBtn.addEventListener('click', () => {
            modal.classList.remove('show');
        });
        
        window.addEventListener('click', (event) => {
            if (event.target === modal) {
                modal.classList.remove('show');
            }
        });
    },

    /**
     * 初始化节点详情浮动面板的交互
     */
    _initFloatPanel() {
        const panel = document.getElementById('nodeDetailPanel');
        if (!panel) return;
        
        // 关闭按钮
        const closeBtn = document.getElementById('btnCloseNodeDetail');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                panel.style.display = 'none';
            });
        }
        
        // 最小化按钮
        const minimizeBtn = document.getElementById('btnMinimizeNodeDetail');
        if (minimizeBtn) {
            minimizeBtn.addEventListener('click', () => {
                panel.classList.toggle('minimized');
                minimizeBtn.textContent = panel.classList.contains('minimized') ? '□' : '─';
            });
        }
        
        // 拖动功能
        const dragHandle = document.getElementById('nodeDetailDragHandle');
        if (dragHandle) {
            let isDragging = false;
            let startX, startY, origX, origY;
            
            dragHandle.addEventListener('mousedown', (e) => {
                // 如果点击的是按钮，不触发拖动
                if (e.target.closest('.float-panel-btn')) return;
                
                isDragging = true;
                const rect = panel.getBoundingClientRect();
                startX = e.clientX;
                startY = e.clientY;
                origX = rect.left;
                origY = rect.top;
                
                // 将 position 改为 fixed 以便自由拖动
                panel.style.position = 'fixed';
                panel.style.left = origX + 'px';
                panel.style.top = origY + 'px';
                panel.style.right = 'auto';
                
                e.preventDefault();
            });
            
            document.addEventListener('mousemove', (e) => {
                if (!isDragging) return;
                
                const dx = e.clientX - startX;
                const dy = e.clientY - startY;
                
                panel.style.left = (origX + dx) + 'px';
                panel.style.top = (origY + dy) + 'px';
            });
            
            document.addEventListener('mouseup', () => {
                isDragging = false;
            });
        }
    },

    /**
     * 初始化重置按钮
     */
    _initResetButton() {
        // 在控制台添加重置按钮
        const consoleCard = document.querySelector('.console-card');
        if (consoleCard) {
            const resetBtn = document.createElement('button');
            resetBtn.className = 'btn-execute';
            resetBtn.style.marginTop = '8px';
            resetBtn.style.width = '100%';
            resetBtn.style.background = 'var(--accent-red)';
            resetBtn.textContent = '🗑️ 重置所有数据';
            resetBtn.addEventListener('click', async () => {
                if (confirm('确定要重置所有数据吗？')) {
                    await API.resetData();
                    await GRAPH.loadData();
                    TIMELINE.clear();
                    RISK_PANEL.loadRiskCards();
                    Store.set('lastNodeCount', 0);
                    Store.set('lastEdgeCount', 0);
                    // 重置后重新加载场景列表
                    await CONSOLE.loadScenarios();
                }
            });
            consoleCard.appendChild(resetBtn);
        }
    },

    /**
     * 显示节点详情弹窗（增强版）
     */
    showNodeModal(nodeDetail) {
        const modal = document.getElementById('nodeModal');
        const body = document.getElementById('modalBody');
        
        if (!nodeDetail) {
            body.innerHTML = '<p>无法获取节点详情</p>';
            modal.classList.add('show');
            return;
        }
        
        const typeLabels = {
            'AIAgent': '🤖 AI 智能体',
            'AIModelInvocation': '🧠 LLM 推理',
            'AgentTool': '🔧 工具调用',
            'Prompt': '💬 提示内容',
            'DomainData': '📦 数据实体',
        };

        // 角色标签映射
        const roleLabels = {
            'input': { icon: '📥', label: '输入参数', color: 'var(--accent-blue)' },
            'output': { icon: '📤', label: '输出结果', color: 'var(--accent-green)' },
            'created': { icon: '📝', label: '环境变更 - 创建', color: 'var(--accent-orange)' },
            'updated': { icon: '📝', label: '环境变更 - 更新', color: 'var(--accent-yellow)' },
        };

        let html = `
            <h2 style="margin-bottom:16px;font-size:18px;">
                ${typeLabels[nodeDetail.type] || nodeDetail.type}: ${nodeDetail.label || nodeDetail.id}
            </h2>
            <div class="detail-field">
                <span class="label">ID</span>
                <div class="value">${nodeDetail.id}</div>
            </div>
            <div class="detail-field">
                <span class="label">类型</span>
                <div class="value">${typeLabels[nodeDetail.type] || nodeDetail.type}</div>
            </div>
        `;

        // DomainData 显示角色
        if (nodeDetail.type === 'DomainData' && nodeDetail.operation) {
            const role = roleLabels[nodeDetail.operation] || { icon: '📦', label: '数据', color: 'var(--text-primary)' };
            html += `
                <div class="detail-field">
                    <span class="label">角色</span>
                    <div class="value" style="color:${role.color};font-weight:600;">${role.icon} ${role.label}</div>
                </div>
            `;
        }

        // 输出结果节点不显示名称
        if (!(nodeDetail.type === 'DomainData' && nodeDetail.operation === 'output')) {
            html += `
                <div class="detail-field">
                    <span class="label">名称</span>
                    <div class="value">${nodeDetail.label || nodeDetail.id}</div>
                </div>
            `;
        }

        if (nodeDetail.app) {
            html += `
                <div class="detail-field">
                    <span class="label">所属 APP</span>
                    <div class="value">${nodeDetail.app}</div>
                </div>
            `;
        }

        if (nodeDetail.is_sensitive) {
            html += `
                <div class="detail-field">
                    <span class="label">敏感数据</span>
                    <div class="value" style="color:var(--accent-red);font-weight:600;">🔒 包含敏感信息</div>
                </div>
            `;
        }

        if (nodeDetail.blocked) {
            html += `
                <div class="detail-field">
                    <span class="label">阻断状态</span>
                    <div class="value blocked">🚫 已阻断</div>
                </div>
                <div class="detail-field">
                    <span class="label">阻断原因</span>
                    <div class="value blocked">${nodeDetail.block_reason || '未知'}</div>
                </div>
            `;
        }

        if (nodeDetail.inputs) {
            html += `
                <div class="detail-field">
                    <span class="label">输入参数</span>
                    <div class="value" style="font-family:monospace;font-size:11px;">${nodeDetail.inputs}</div>
                </div>
            `;
        }

        if (nodeDetail.content) {
            html += `
                <div class="detail-field">
                    <span class="label">内容</span>
                    <div class="value">${nodeDetail.content}</div>
                </div>
            `;
        }

        if (nodeDetail.prompt) {
            html += `
                <div class="detail-field">
                    <span class="label">Prompt</span>
                    <div class="value" style="font-family:monospace;font-size:11px;background:var(--bg-card);padding:8px;border-radius:4px;">
                        ${nodeDetail.prompt.substring(0, 200)}${nodeDetail.prompt.length > 200 ? '...' : ''}
                    </div>
                </div>
            `;
        }

        if (nodeDetail.response) {
            html += `
                <div class="detail-field">
                    <span class="label">LLM 响应</span>
                    <div class="value" style="font-family:monospace;font-size:11px;background:var(--bg-card);padding:8px;border-radius:4px;">
                        ${nodeDetail.response.substring(0, 200)}${nodeDetail.response.length > 200 ? '...' : ''}
                    </div>
                </div>
            `;
        }

        body.innerHTML = html;
        modal.classList.add('show');
    },

    /**
     * 启动定时轮询（增量更新检测）
     */
    _startPolling() {
        if (Store.get('isPolling')) return;
        Store.set('isPolling', true);
        
        // 每 5 秒检查一次新数据
        setInterval(async () => {
            try {
                const data = await API.getGraphData();
                if (data && data.graph) {
                    const newNodeCount = data.graph.nodes.length;
                    const newEdgeCount = data.graph.links.length;
                    const oldNodeCount = Store.get('lastNodeCount');
                    const oldEdgeCount = Store.get('lastEdgeCount');
                    
                    // 增量更新检测：只在新数据有变化时更新
                    if (newNodeCount !== oldNodeCount || newEdgeCount !== oldEdgeCount) {
                        console.log(`📊 检测到新数据: +${newNodeCount - oldNodeCount} 节点, +${newEdgeCount - oldEdgeCount} 边`);
                        
                        // 使用 setData 确保引用一致性
                        GRAPH.setData(data.graph.nodes, data.graph.links);
                        GRAPH.render();
                        GRAPH.updateStats(data.summary);
                        
                        Store.set('lastNodeCount', newNodeCount);
                        Store.set('lastEdgeCount', newEdgeCount);
                        
                        if (data.events) {
                            TIMELINE.loadEvents(data.events);
                        }
                        
                        RISK_PANEL.loadRiskCards();
                    }
                }
            } catch (err) {
                // 静默处理轮询错误
            }
        }, 5000);
    }
};

// ============================================================
// 页面加载完成后启动应用
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    APP.init();
});
