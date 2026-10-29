#!/usr/bin/env node
/**
 * Check a saved trace graph for card overlap without launching a browser.
 *
 * Usage:
 *   node util_scripts/check_graph_layout.js path/to/trace.json
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const tracePath = process.argv[2];
if (!tracePath) {
    console.error('Usage: node util_scripts/check_graph_layout.js <trace.json>');
    process.exit(2);
}

const trace = JSON.parse(fs.readFileSync(tracePath, 'utf8'));
const graphData = trace.graph || trace;
const graphSource = fs.readFileSync(
    path.join(__dirname, '..', 'frontend', 'js', 'graph.js'),
    'utf8'
);
const appCatalogSource = fs.readFileSync(
    path.join(__dirname, '..', 'frontend', 'js', 'app-catalog.js'),
    'utf8'
);
const context = {
    console,
    Set,
    Map,
    Math,
    JSON,
    String,
    Number,
    Array,
    Object,
    window: {},
    requestAnimationFrame: callback => callback(),
};
vm.createContext(context);
vm.runInContext(appCatalogSource, context);
vm.runInContext(`${graphSource}\nthis.__GRAPH__ = GRAPH;`, context);

const graph = context.__GRAPH__;
graph.config.width = 1440;
graph.config.height = 900;
graph.config.linkMode = process.argv[3] === 'audit' ? 'audit' : 'flow';
graph.setData(
    graphData.nodes.map(node => ({ ...node })),
    graphData.links.map(link => ({ ...link })),
    {}
);

graph._prepareNodeViews();
graph._computeStructuredLayout();
const visibleLinks = graph._visibleLinks();
graph._prepareLinkRoutes(graph.nodes, visibleLinks);
visibleLinks.forEach(link => graph._linkPath(link));
const displayLinks = visibleLinks.filter(link => (
    !link.__bundleHidden && !link.__contextHidden
));

const boxes = graph.nodes.map(node => {
    const view = node.__view || { width: 96, height: 46 };
    return {
        id: node.id,
        type: node.type,
        x1: node.x - view.width / 2,
        y1: node.y - view.height / 2,
        x2: node.x + view.width / 2,
        y2: node.y + view.height / 2,
    };
});

const overlaps = [];
for (let i = 0; i < boxes.length; i += 1) {
    for (let j = i + 1; j < boxes.length; j += 1) {
        const a = boxes[i];
        const b = boxes[j];
        if (a.x1 < b.x2 && a.x2 > b.x1 && a.y1 < b.y2 && a.y2 > b.y1) {
            overlaps.push([a, b]);
        }
    }
}

const headers = (graph._columns || []).map(column => {
    const width = Math.max(36, String(column.label || '').length * 12);
    return {
        id: `column:${column.key}`,
        x1: column.x - width / 2,
        y1: 8,
        x2: column.x + width / 2,
        y2: 32,
    };
});
const headerOverlaps = [];
for (const box of boxes) {
    for (const header of headers) {
        if (
            box.x1 < header.x2
            && box.x2 > header.x1
            && box.y1 < header.y2
            && box.y2 > header.y1
        ) {
            headerOverlaps.push({
                node: `${box.type}:${box.id}`,
                header: header.id,
            });
        }
    }
}

const edgeNodeCollisions = [];
visibleLinks.forEach((link) => {
    const sourceId = link.source.id || link.source;
    const targetId = link.target.id || link.target;
    const points = link.__routePoints || [];
    const samples = link.__curveSamples || [];
    boxes.forEach((box) => {
        if (box.id === sourceId || box.id === targetId) return;
        let collides = false;
        for (let index = 1; index < points.length; index += 1) {
            const from = points[index - 1];
            const to = points[index];
            const left = Math.min(from.x, to.x);
            const right = Math.max(from.x, to.x);
            const top = Math.min(from.y, to.y);
            const bottom = Math.max(from.y, to.y);
            if (
                right >= box.x1
                && left <= box.x2
                && bottom >= box.y1
                && top <= box.y2
            ) {
                collides = true;
                break;
            }
        }
        if (!collides) {
            collides = samples.some(point => (
                point.x >= box.x1
                && point.x <= box.x2
                && point.y >= box.y1
                && point.y <= box.y2
            ));
        }
        if (collides) {
            edgeNodeCollisions.push({
                relation: link.relation,
                source: sourceId,
                target: targetId,
                node: `${box.type}:${box.id}`,
            });
        }
    });
});

const edgeOverlaps = [];
for (let i = 0; i < visibleLinks.length; i += 1) {
    const first = visibleLinks[i];
    const firstSamples = (first.__curveSamples || []).slice(2, -2);
    if (firstSamples.length < 3) continue;
    for (let j = i + 1; j < visibleLinks.length; j += 1) {
        const second = visibleLinks[j];
        const secondSamples = (second.__curveSamples || []).slice(2, -2);
        if (secondSamples.length < 3) continue;
        let closeSamples = 0;
        firstSamples.forEach((point) => {
            const nearest = Math.min(...secondSamples.map(other => (
                Math.hypot(point.x - other.x, point.y - other.y)
            )));
            if (nearest < 0.5) closeSamples += 1;
        });
        if (closeSamples >= 3) {
            edgeOverlaps.push({
                first: `${first.source.id}:${first.relation}:${first.target.id}`,
                second: `${second.source.id}:${second.relation}:${second.target.id}`,
                close_samples: closeSamples,
            });
        }
    }
}

console.log(JSON.stringify({
    trace_id: trace.trace_id || null,
    link_mode: graph.config.linkMode,
    nodes: boxes.length,
    visible_links: visibleLinks.length,
    display_links: displayLinks.length,
    positions: boxes.map(box => ({
        type: box.type,
        id: box.id,
        x: Number(((box.x1 + box.x2) / 2).toFixed(1)),
        y: Number(((box.y1 + box.y2) / 2).toFixed(1)),
    })),
    overlaps: overlaps.map(([a, b]) => ({
        a: `${a.type}:${a.id}`,
        b: `${b.type}:${b.id}`,
    })),
    header_overlaps: headerOverlaps,
    edge_node_collisions: edgeNodeCollisions,
    edge_overlaps: edgeOverlaps,
}, null, 2));
process.exitCode = overlaps.length
    || headerOverlaps.length
    || edgeNodeCollisions.length
    || edgeOverlaps.length
    ? 1
    : 0;
