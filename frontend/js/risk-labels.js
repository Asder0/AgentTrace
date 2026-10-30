/** Structured Chinese labels for security and policy events. */
(function (global) {
    'use strict';

    const ringTitles = {
        0: 'Ring 0：直接提示注入检测',
        1: 'Ring 1：不可信控制流检查',
        2: 'Ring 2：任务工具范围检查',
        3: 'Ring 3：敏感数据外发检查',
    };

    const fsmStateLabels = {
        CONTEXT_READY: '上下文就绪',
        ACTION_PROPOSED: '动作已提出',
        ADMITTED: '已放行',
        SANITIZED: '已隔离处理',
        OUTPUT_OBSERVED: '输出已观测',
        ADVISED: '已告警',
        HELD: '等待确认',
        BLOCKED: '已阻断',
        COMPLETED: '已完成',
        FAILED: '失败',
        INCOMPLETE: '未完成',
        QUARANTINED: '已隔离',
        CANCELLED: '已取消',
    };

    const decisionLabels = {
        PASS: '通过',
        ADVISORY: '告警',
        MITIGATE: '缓解',
        QUARANTINE: '隔离',
        HOLD: '等待确认',
        BLOCK: '阻断',
    };

    const severityLabels = {
        low: '低',
        medium: '中',
        high: '高',
        critical: '严重',
    };

    const confidentialityLabels = {
        public: '公开',
        internal: '内部',
        confidential: '机密',
        secret: '秘密',
    };

    const provenanceStateLabels = {
        complete: '来源完整',
        verified: '来源已验证',
        unknown: '存在未验证来源',
        incomplete: '来源不完整',
        invalid: '来源无效',
        not_evaluated: '未评估',
    };

    const effectLabels = {
        read: '读取',
        write: '写入',
        egress: '外发',
        privilege: '权限变更',
        unknown: '未知',
    };

    const categoryLabels = {
        email: '邮件',
        financial_data: '金融数据',
        banking: '银行数据',
        credential: '凭证',
        credentials: '凭证',
        identity: '身份信息',
        personal_data: '个人信息',
        calendar: '日历',
        file: '文件',
        files: '文件',
        hotel: '酒店',
        channel: '频道',
        account: '账户',
    };

    const integrityLabels = {
        trusted: '可信',
        untrusted: '不可信',
        tainted: '已污染',
    };

    const taskStateLabels = {
        BLOCKED: '已阻断',
        COMPLETED: '已完成',
        FAILED: '失败',
        INCOMPLETE: '未完成',
        CANCELLED: '已取消',
        QUARANTINED: '已隔离',
    };

    const layerLabels = {
        Capture: '数据捕获',
        Modeling: '溯源建模',
        Analysis: '风险分析',
        Visualization: '可视化服务',
        Execution: '执行服务',
    };

    const sourceStatusLabels = {
        resolved: '已解析',
        unresolved: '未解析',
        blocked: '已阻断',
        failed: '失败',
        pending: '待处理',
    };

    const injectionStatusLabels = {
        scanned_clean: '扫描正常',
        not_applicable: '无需扫描',
        quarantined: '已隔离',
        flagged: '已标记风险',
        unscanned: '未扫描',
        unavailable: '扫描不可用',
    };

    const planBehaviorLabels = {
        finish: '结束任务',
        finish_without_side_effects: '安全结束，不执行副作用',
    };

    const generationKindLabels = {
        copy: '来源字段复制',
        extraction: '来源字段提取',
        normalization: '来源字段规范化',
        selection: '多来源候选选择',
        calculation: '来源数据计算',
        summary: '来源内容摘要',
        presentation: '受来源约束的模型生成文本',
        auto: '受来源约束的模型派生',
    };

    function titleFor(ring, policyId) {
        if (policyId === 'ring0.direct_user_instruction') {
            return 'Ring 0：直接提示注入检测';
        }
        if (policyId === 'ring1.indirect_prompt_injection') {
            return 'Ring 1：间接提示注入隔离';
        }
        if (policyId === 'ring1.untrusted_control') {
            return 'Ring 1：不可信控制参数提醒';
        }
        if (policyId === 'ring2.requirement_coverage') {
            return 'Ring 2\uff1a\u4efb\u52a1\u8981\u6c42\u8986\u76d6\u68c0\u67e5';
        }
        if (policyId === 'ring2.l2_chain_inconsistent') {
            return 'Ring 2：L2 调用链检查';
        }
        if (policyId === 'ring2.l2_confirmation') {
            return 'Ring 2：L2 人工确认';
        }
        if (policyId === 'ring2.sensitive_data_exposure_confirmation') {
            return 'Ring 2：敏感数据读取授权';
        }
        if (policyId === 'ring2.sensitive_data_exposure_rejected') {
            return 'Ring 2：敏感数据读取拒绝';
        }
        if (policyId === 'ring2.sensitive_data_exposure_stale') {
            return 'Ring 2：敏感数据授权失效';
        }
        if (policyId === 'ring2.l2_confirmation_rejected') {
            return 'Ring 2：L2 人工授权结果';
        }
        if (policyId === 'ring2.source_risk_confirmation') {
            return 'Ring 2\uff1a\u53ef\u7591\u6765\u6e90\u5199\u64cd\u4f5c\u4eba\u5de5\u786e\u8ba4';
        }
        if (policyId === 'ring2.l2_confirmation_stale') {
            return 'Ring 2\uff1a\u4eba\u5de5\u6388\u6743\u5df2\u5931\u6548';
        }
        if (policyId === 'ring2.task_scope_unavailable') {
            return 'Ring 2：任务授权不可用';
        }
        if (policyId === 'ring2.sensitive_field_withheld') {
            return 'Ring 2：敏感字段已隔离';
        }
        if (String(policyId).startsWith('ring2.task_scope')) {
            return 'Ring 2：任务范围策略';
        }
        if (policyId === 'ring3.sensitive_egress') {
            return 'Ring 3：敏感数据外发检查';
        }
        return ringTitles[ring] || `Ring ${ring}：安全事件`;
    }

    function actionFor(decision, ring, policyId) {
        const normalized = String(decision || 'ADVISORY').toUpperCase();
        if (normalized === 'MITIGATE') {
            if (policyId === 'ring1.indirect_prompt_injection') {
                return '隔离高风险内容';
            }
            if (ring === 0) {
                return '隔离注入片段';
            }
            return '最小化敏感数据';
        }
        return decisionLabels[normalized] || normalized;
    }

    function localizeFsmState(state) {
        const value = String(state || '').trim();
        return fsmStateLabels[value] || value || '未知';
    }

    function effectFor(decision, ring, policyId, before, after) {
        if (before && after) {
            return `状态：${localizeFsmState(before)} → ${localizeFsmState(after)}`;
        }
        const normalized = String(decision || 'ADVISORY').toUpperCase();
        return {
            PASS: '允许执行',
            ADVISORY: '记录风险后继续执行',
            MITIGATE: ring === 0
                ? '注入片段已隔离'
                : policyId === 'ring1.indirect_prompt_injection'
                    ? '高风险内容已隔离，任务继续'
                    : '风险内容已最小化',
            QUARANTINE: '风险内容已隔离',
            HOLD: '暂停执行，等待人工决策',
            BLOCK: '已在副作用发生前阻断',
        }[normalized] || '已记录防护决策';
    }

    function detailFor(card, decision, ring, policyId) {
        const action = card.action || card.tool_name || '当前操作';
        if (policyId === 'ring0.direct_user_instruction') {
            if (decision === 'MITIGATE') {
                return '用户输入中的直接注入片段已隔离，可信任务内容继续执行。';
            }
            if (decision === 'ADVISORY') {
                return '用户输入疑似包含指令操纵，已保留审计告警。';
            }
            return '用户输入存在直接提示注入，任务已阻断。';
        }
        if (policyId === 'ring1.indirect_prompt_injection') {
            return '工具输出中检测到间接提示注入内容，高风险分块已在进入后续推理前隔离。';
        }
        if (policyId === 'ring1.untrusted_control') {
            return '工具输出中的不可信数据影响了控制参数，已保留来源风险标签并记录审计告警。';
        }
        if (policyId === 'ring2.l2_confirmation') {
            return `“${action}”属于计划内 L2 操作，调用链检查通过，等待人工确认。`;
        }
        if (policyId === 'ring2.sensitive_data_exposure_confirmation') {
            return `“${action}”需要读取任务必需的敏感字段，等待用户授权。`;
        }
        if (policyId === 'ring2.sensitive_data_exposure_rejected') {
            return `“${action}”的敏感字段读取未获授权，读取已阻断。`;
        }
        if (policyId === 'ring2.l2_confirmation_rejected') {
            return `“${action}”未获得人工授权，操作已阻断。`;
        }
        if (policyId === 'ring2.source_risk_confirmation') {
            return `\u201c${action}\u201d\u53d7\u53ef\u7591\u6765\u6e90\u5f71\u54cd\uff0c\u505c\u6b62\u6267\u884c\u5e76\u7b49\u5f85\u4eba\u5de5\u786e\u8ba4\u3002`;
        }
        if (policyId === 'ring2.l2_confirmation_stale') {
            return `\u201c${action}\u201d\u7684\u8ba1\u5212\u6216\u53c2\u6570\u5df2\u53d1\u751f\u53d8\u5316\uff0c\u539f\u4eba\u5de5\u6388\u6743\u4e0d\u518d\u9002\u7528\u3002`;
        }
        if (policyId === 'ring2.requirement_coverage') {
            return `\u201c${action}\u201d\u8fd8\u6709\u672a\u9a8c\u8bc1\u6216\u76f8\u4e92\u51b2\u7a81\u7684\u4efb\u52a1\u8981\u6c42\uff0c\u672c\u6b21 L2 \u64cd\u4f5c\u672a\u6267\u884c\u3002\u8bf7\u5148\u5b8c\u6210\u9700\u8981\u7684 L0/L1 \u53ea\u8bfb\u9a8c\u8bc1\uff0c\u6216\u5411\u7528\u6237\u8bf4\u660e\u65e0\u6cd5\u540c\u65f6\u6ee1\u8db3\u7684\u6761\u4ef6\u3002`;
        }
        if (policyId === 'ring2.l2_chain_inconsistent') {
            return `“${action}”与授权任务调用链不一致，操作已阻断。`;
        }
        if (policyId === 'ring2.task_scope_unavailable') {
            return '当前任务授权契约不可用，高风险操作已阻断。';
        }
        if (policyId === 'ring2.sensitive_field_withheld') {
            return '字段内容触发敏感类别升级，超过本次读取允许范围，相关字段已在进入 Agent 前隔离。';
        }
        if (String(policyId).startsWith('ring2.task_scope')) {
            return decision === 'ADVISORY'
                ? `“${action}”不在当前任务计划的显式范围内，已记录告警。`
                : `“${action}”不在当前任务授权范围内，操作已阻断。`;
        }
        if (policyId === 'ring3.sensitive_egress') {
            return '外发内容涉及敏感数据，但接收方、数据来源或敏感等级校验未通过，操作已阻断。';
        }
        if (policyId === 'legacy.block_reason') {
            return '旧版安全事件没有结构化策略编号，已按阻断事件记录。';
        }
        return ring === 1
            ? '不可信内容触发了审计提醒，已记录风险标签。'
            : '安全策略已记录本次防护决策。';
    }

    function confidentialityLabel(value) {
        const key = String(value || '').toLowerCase();
        return confidentialityLabels[key] || value || '未知';
    }

    function provenanceStateLabel(value) {
        const key = String(value || '').toLowerCase();
        return provenanceStateLabels[key] || value || '未知';
    }

    function warningLabel(warning) {
        const text = String(warning || '').trim();
        if (!text) return '';
        const [code, subject = ''] = text.split(':', 2);
        const labels = {
            semantic_derivation_unverified:
                `参数${subject ? `“${subject}”` : ''}为语义汇总，来源内容无法逐字复核`,
            required_source_evidence_missing:
                `缺少必需来源证据${subject ? `：${subject}` : ''}`,
            unauthorized_source_ref:
                `参数${subject ? `“${subject}”` : ''}引用了未授权来源`,
            derived_source_evidence_missing:
                `参数${subject ? `“${subject}”` : ''}无法关联到可信字段`,
            parameter_required_sources_missing:
                `参数${subject ? `“${subject}”` : ''}未声明必选数据来源`,
            required_parameter_source_missing:
                `参数${subject ? `“${subject}”` : ''}缺少一个或多个必选来源`,
            derived_source_evidence_not_found:
                `参数${subject ? `“${subject}”` : ''}引用的字段证据不存在`,
            derived_source_evidence_ambiguous:
                `参数${subject ? `“${subject}”` : ''}的字段证据存在歧义`,
            derived_source_span_mismatch:
                `参数${subject ? `“${subject}”` : ''}的证据区间不匹配`,
            derived_evidence_value_mismatch:
                `参数${subject ? `“${subject}”` : ''}与引用证据不一致`,
            parameter_value_mismatch:
                `参数${subject ? `“${subject}”` : ''}的最终值与解析器验证值不一致`,
            parameter_verified_value_missing:
                `参数${subject ? `“${subject}”` : ''}缺少解析器验证值`,
            derivation_type_mismatch:
                `参数${subject ? `“${subject}”` : ''}的派生方式与计划不一致`,
            selection_value_not_in_candidates:
                `参数${subject ? `“${subject}”` : ''}的选中值不在候选来源中`,
            unresolved_placeholder_in_payload:
                '发送参数中仍存在未解析的控制器占位符',
            data_source_unresolved:
                '无法确认外发内容的原始数据来源',
            data_source_not_authorized:
                '外发内容包含未授权数据来源',
            confidentiality_exceeds_sink_limit:
                '内容敏感等级超过接收方允许上限',
            destination_not_authorized:
                '接收方不在当前授权范围内',
        };
        return labels[code] || `来源校验存在提醒（${code}）`;
    }

    function effectLabel(value) {
        const key = String(value || '').toLowerCase();
        return effectLabels[key] || value || '未知';
    }

    function categoryLabel(value) {
        const key = String(value || '').toLowerCase();
        return categoryLabels[key] || value || '未知';
    }

    function integrityLabel(value) {
        const key = String(value || '').toLowerCase();
        return integrityLabels[key] || value || '未知';
    }

    function taskStateLabel(value) {
        const key = String(value || '').toUpperCase();
        return taskStateLabels[key] || value || '未知';
    }

    function layerLabel(value) {
        return layerLabels[value] || value || '未知';
    }

    function sourceStatusLabel(value) {
        const key = String(value || '').toLowerCase();
        return sourceStatusLabels[key] || value || '未知';
    }

    function injectionStatusLabel(value) {
        const key = String(value || '').toLowerCase();
        return injectionStatusLabels[key] || value || '未知';
    }

    function planBehaviorLabel(value) {
        return planBehaviorLabels[value] || value || '结束任务';
    }

    function generationKindLabel(value) {
        const key = String(value || '').toLowerCase();
        return generationKindLabels[key] || value || '未知';
    }

    function hasChinese(value) {
        return /[\u3400-\u9fff]/u.test(String(value || ''));
    }

    function auditSummaryText(kind, item, outcomeCounts = {}) {
        if (kind === 'blocked') return '安全策略已阻断该操作。';
        if (kind === 'mitigated') return '检测到不可信内容，高风险部分已隔离。';
        if (kind === 'advisory') return '检测到不可信内容影响，已记录审计提醒。';
        if (kind === 'completed') {
            return '所有必需结果均已完成并通过证据核验。';
        }
        if (kind === 'incomplete') {
            const missing = Number(outcomeCounts.unsatisfied || 0);
            const uncertain = Number(outcomeCounts.uncertain || 0);
            return [
                '任务未完成。',
                missing ? `${missing} 项必需结果未满足。` : '',
                uncertain ? `${uncertain} 项结果无法验证。` : '',
            ].filter(Boolean).join('');
        }
        return '审计状态已记录。';
    }

    function confirmationReason(request) {
        const chain = request?.chain_check || {};
        const flow = request?.flow_check || {};
        if (request?.confirmation_kind === 'sensitive_data_exposure') {
            return '该读取会把任务必需且需要比较分析的敏感字段交给 Agent。未列入待查看或搬运范围的字段已在进入 Agent 前隐藏；请结合左侧溯源图谱确认字段范围和任务必要性后决定是否授权。';
        }
        if (chain.consistent === false) {
            return '调用链检查未通过。该操作与当前授权任务或计划步骤不一致，请拒绝执行并检查溯源证据。';
        }
        if (chain.manual_review_notes?.length) {
            return '该操作属于计划内 L2 动作，结构化检查已通过；自然语言参数不做自动事实校验，请人工核对正文与来源后决定是否执行。';
        }
        if (flow.provenance_warnings?.length) {
            return '该操作属于计划内 L2 动作，接收方和数据来源已通过基础校验，但存在需要关注来源完整性提醒。请结合左侧溯源图谱确认。';
        }
        return '该操作属于计划内 L2 动作，调用链、接收方和数据来源检查已通过。请结合左侧溯源图谱确认是否执行。';
    }

    function confirmationSummary(request) {
        const chain = request?.chain_check || {};
        const flow = request?.flow_check || {};
        if (request?.confirmation_kind === 'sensitive_data_exposure') {
            const exposure = chain.exposure_check || {};
            return [
                `待查看字段：${(exposure.inspection_fields || []).join(', ') || '-'}`,
                `占位符搬运字段：${(exposure.opaque_fields || []).join(', ') || '无'}`,
                `暴露上限：${exposure.max_exposure_level || '-'}`,
            ].join(' · ');
        }
        const confidence = Number(chain.confidence);
        return [
            `调用链检查：${chain.consistent === false ? '未通过' : '通过'}`,
            Number.isFinite(confidence)
                ? `判定置信度：${Math.round(confidence * 100)}%`
                : '',
            `来源状态：${provenanceStateLabel(flow.provenance_state)}`,
            `字段级来源：${(flow.provenance_refs || flow.field_sources || []).length} 条`,
            chain.manual_review_notes?.length
                ? `人工核对提示：${chain.manual_review_notes.length} 项`
                : '',
        ].filter(Boolean).join(' · ');
    }

    function normalizeCard(card) {
        if (!card || typeof card !== 'object') return card;
        const ring = Number.isInteger(Number(card.ring))
            ? Number(card.ring)
            : 0;
        const decision = String(card.decision || 'ADVISORY').toUpperCase();
        const policyId = String(card.policy_id || '');
        let title = titleFor(ring, policyId);
        if (
            decision === 'MITIGATE'
            && ring === 0
            && policyId.startsWith('ring0.')
        ) {
            title = 'Ring 0：直接提示注入隔离';
        }
        const severity = String(card.severity || 'medium').toLowerCase();
        return {
            ...card,
            ring,
            decision,
            title,
            decision_label: decisionLabels[decision] || decision,
            severity_label: severityLabels[severity] || severity,
            defense_ring: title,
            defense_action: actionFor(decision, ring, policyId),
            defense_effect: effectFor(
                decision,
                ring,
                policyId,
                card.fsm_before,
                card.fsm_after,
            ),
            defense_detail: detailFor(
                card,
                decision,
                ring,
                policyId,
            ),
        };
    }

    global.AgentTraceRiskLabels = {
        titleFor,
        actionFor,
        effectFor,
        detailFor,
        confidentialityLabel,
        provenanceStateLabel,
        warningLabel,
        effectLabel,
        categoryLabel,
        integrityLabel,
        taskStateLabel,
        layerLabel,
        sourceStatusLabel,
        injectionStatusLabel,
        planBehaviorLabel,
        generationKindLabel,
        hasChinese,
        auditSummaryText,
        confirmationReason,
        confirmationSummary,
        normalizeCard,
        localizeFsmState,
        decisionLabels,
        severityLabels,
        confidentialityLabels,
        provenanceStateLabels,
        effectLabels,
        categoryLabels,
        integrityLabels,
        taskStateLabels,
        layerLabels,
        generationKindLabels,
    };
})(window);
