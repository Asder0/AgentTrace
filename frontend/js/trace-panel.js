/**
 * 指令流转追踪（兼容层）
 *
 * 原先右侧独立的“指令流转追踪”面板已合并进底部“执行时间线”，
 * 避免同一批 LLM / 工具调用在两个位置重复展示。
 *
 * 本模块仅保留原有调用入口，转发给 TIMELINE：
 * - _renderTrace(trace)：用 steps + events 刷新底部时间线
 * - clear()：清除时间线中的步骤信息
 */

const TRACE_PANEL = {
    init() {
        // 不再创建右侧面板，时间线由 TIMELINE 负责初始化
    },

    _renderTrace(trace) {
        if (typeof TIMELINE === 'undefined') return;
        if (TIMELINE.setTrace) {
            TIMELINE.setTrace(trace);
        }
    },

    clear() {
        if (typeof TIMELINE === 'undefined') return;
        if (TIMELINE.clearTraceSteps) {
            TIMELINE.clearTraceSteps();
        }
    },
};
