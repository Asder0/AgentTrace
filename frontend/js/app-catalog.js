(function (global) {
    'use strict';

    const SUITES = Object.freeze([
        'system',
        'banking',
        'workspace',
        'slack',
        'travel',
    ]);
    const MODULE_OWNERS = Object.freeze({
        banking: ['banking'],
        banking_client: ['banking'],
        file_reader: ['banking'],
        user_account: ['banking'],
        email: ['workspace', 'travel'],
        email_client: ['workspace', 'travel'],
        calendar: ['workspace', 'travel'],
        calendar_client: ['workspace', 'travel'],
        cloud_drive: ['workspace'],
        cloud_drive_client: ['workspace'],
        slack: ['slack'],
        web: ['slack'],
        travel: ['travel'],
        travel_booking_client: ['travel'],
    });
    const LABELS = Object.freeze({
        system: '系统',
        banking: '银行',
        workspace: '办公',
        slack: '通讯',
        travel: '旅行',
        unified: '统一',
    });

    function canonicalApp(value, suite = '') {
        const raw = String(value == null ? '' : value).trim();
        if (!raw) return '';
        if (raw === 'unknown') return 'unknown';
        if (SUITES.includes(raw)) return raw;

        const contextSuite = String(suite || '').trim();
        const owners = MODULE_OWNERS[raw] || [];
        if (contextSuite && owners.includes(contextSuite)) return contextSuite;
        if (owners.length === 1) return owners[0];
        if (owners.length > 1) return 'unified';
        return raw;
    }

    function appLabel(value) {
        const app = canonicalApp(value);
        return LABELS[app] || app || '';
    }

    global.AgentTraceAppCatalog = Object.freeze({
        SUITES,
        canonicalApp,
        appLabel,
    });
})(window);
