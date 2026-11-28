/**
 * API client for the same-origin Flask service.
 *
 * All non-2xx responses use the structured API error contract:
 * { error: { code, message, retryable, request_id } }.
 */

class ApiError extends Error {
    constructor(message, {
        code = 'request_failed',
        status = 0,
        retryable = false,
        requestId = '',
    } = {}) {
        super(message);
        this.name = 'ApiError';
        this.code = code;
        this.status = status;
        this.retryable = retryable;
        this.requestId = requestId;
    }
}

const API = {
    BASE_URL: '/api',

    async _request(path, options = {}, timeoutMs = 0) {
        const controller = timeoutMs > 0 ? new AbortController() : null;
        const timeoutId = controller
            ? setTimeout(() => controller.abort(), timeoutMs)
            : null;
        try {
            const response = await fetch(`${this.BASE_URL}${path}`, {
                ...options,
                signal: controller?.signal,
            });
            const text = await response.text();
            let payload = null;
            if (text) {
                try {
                    payload = JSON.parse(text);
                } catch (_error) {
                    payload = text;
                }
            }
            const structured = payload?.error;
            if (!response.ok || structured) {
                const message = (
                    typeof structured === 'string'
                        ? structured
                        : structured?.message
                ) || `请求失败（HTTP ${response.status}）`;
                throw new ApiError(message, {
                    code: structured?.code || 'request_failed',
                    status: response.status,
                    retryable: Boolean(structured?.retryable),
                    requestId: (
                        structured?.request_id
                        || response.headers.get('X-Request-ID')
                        || ''
                    ),
                });
            }
            return payload;
        } catch (error) {
            if (error instanceof ApiError) throw error;
            if (error?.name === 'AbortError') {
                throw new ApiError('请求超时，请稍后重试。', {
                    code: 'timeout',
                    retryable: true,
                });
            }
            throw new ApiError('无法连接本地服务，请确认后端仍在运行。', {
                code: 'network_error',
                retryable: true,
            });
        } finally {
            if (timeoutId !== null) clearTimeout(timeoutId);
        }
    },

    formatError(error, prefix = '') {
        const message = error instanceof Error
            ? error.message
            : String(error || '未知错误');
        const requestId = error?.requestId
            ? `（请求编号：${error.requestId}）`
            : '';
        return `${prefix}${message}${requestId}`;
    },

    getGraphData() {
        return this._request(
            '/graph',
            { headers: { 'Accept': 'application/json' } },
            5000,
        );
    },

    getRiskCards() {
        return this._request('/risk-cards');
    },

    getPolicyEvents() {
        return this._request('/policy-events');
    },

    getScenarios() {
        return this._request('/scenarios');
    },

    executeAction(action, runtimeOptions = {}) {
        return this._request('/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action,
                ...runtimeOptions,
            }),
        });
    },

    resetData() {
        return this._request('/reset', { method: 'POST' });
    },

    getSystemStatus() {
        return this._request('/status');
    },

    getLLMConfig() {
        return this._request('/config/llm');
    },

    setLLMConfig(config) {
        return this._request('/config/llm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config),
        });
    },

    getDefenseConfig() {
        return this._request('/config/defense');
    },

    getTraces() {
        return this._request('/traces');
    },

    getTrace(traceId) {
        return this._request(
            `/traces/${encodeURIComponent(traceId)}`,
        );
    },

    setDefenseConfig(
        enabled,
        rings = null,
        directInjectionMode = null,
        autoConfirmations = null,
    ) {
        const body = {};
        if (enabled !== null && enabled !== undefined) {
            body.enabled = enabled;
        }
        if (rings) body.rings = rings;
        if (directInjectionMode) {
            body.direct_injection_mode = directInjectionMode;
        }
        if (
            autoConfirmations !== null
            && autoConfirmations !== undefined
        ) {
            body.auto_confirmations = autoConfirmations;
        }
        return this._request('/config/defense', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
    },

    getPendingConfirmations() {
        return this._request('/confirmations');
    },

    resolveConfirmation(requestId, approved) {
        return this._request(
            `/confirmations/${encodeURIComponent(requestId)}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ approved: !!approved }),
            },
        );
    },

    resolveRequirementDecision(requestId, decision) {
        return this._request(
            `/confirmations/${encodeURIComponent(requestId)}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ decision }),
            },
        );
    },

    getCrossAppAttackTargets() {
        return this._request('/attack/cross-app-targets');
    },

    executeAttack(params) {
        return this._request('/execute/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params),
        });
    },

    getStorageSuites() {
        return this._request('/storage/suites');
    },

    getStorageSuite(suite, include = 'both') {
        const params = new URLSearchParams({ include });
        return this._request(
            `/storage/suites/${encodeURIComponent(suite)}?${params}`,
        );
    },
};
