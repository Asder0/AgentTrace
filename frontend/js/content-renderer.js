/**
 * Safe, dependency-free rendering for model and tool output.
 *
 * The renderer accepts text or structured values and produces escaped HTML.
 * It supports headings, paragraphs, lists, code blocks, links and Markdown
 * tables. Raw HTML in model output is always treated as text.
 */
const AgentTraceContent = (() => {
    const HTML_ESCAPE = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
    };

    function escapeHtml(value) {
        return String(value == null ? '' : value).replace(
            /[&<>"']/g,
            character => HTML_ESCAPE[character],
        );
    }

    function asText(value) {
        if (value == null) return '';
        if (typeof value === 'string') return value;
        if (typeof value === 'number' || typeof value === 'boolean') {
            return String(value);
        }
        try {
            return JSON.stringify(value, null, 2);
        } catch (_error) {
            return String(value);
        }
    }

    function tryParseJson(text) {
        const trimmed = String(text || '').trim();
        if (!trimmed || !['{', '['].includes(trimmed[0])) return null;
        try {
            return JSON.parse(trimmed);
        } catch (_error) {
            return null;
        }
    }

    function inlineMarkdown(text) {
        const codeSpans = [];
        let html = escapeHtml(text).replace(
            /`([^`\n]+)`/g,
            (_match, code) => {
                const token = `\u0000CODE${codeSpans.length}\u0000`;
                codeSpans.push(`<code>${code}</code>`);
                return token;
            },
        );
        html = html.replace(
            /\[([^\]]+)\]\((https?:\/\/[^\s)]+|mailto:[^\s)]+)\)/g,
            (_match, label, url) => (
                `<a href="${url}" target="_blank" rel="noopener noreferrer">`
                + `${label}</a>`
            ),
        );
        html = html
            .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
            .replace(/(^|[\s(])\*([^*\n]+)\*(?=$|[\s).,!?:;])/g, '$1<em>$2</em>')
            .replace(/~~([^~\n]+)~~/g, '<del>$1</del>');
        html = html.replace(
            /\u0000CODE(\d+)\u0000/g,
            (_match, index) => codeSpans[Number(index)] || '',
        );
        return html;
    }

    function splitTableRow(line) {
        let source = String(line || '').trim();
        if (source.startsWith('|')) source = source.slice(1);
        if (source.endsWith('|')) source = source.slice(0, -1);
        source = source.replace(/\\\|/g, '\u0000PIPE\u0000');
        return source.split('|').map(cell =>
            cell.replace(/\u0000PIPE\u0000/g, '|').trim()
        );
    }

    function isTableSeparator(line) {
        const cells = splitTableRow(line);
        return cells.length > 0 && cells.every(cell =>
            /^:?-{3,}:?$/.test(cell)
        );
    }

    function tableAlignment(separator) {
        return splitTableRow(separator).map(cell => {
            const left = cell.startsWith(':');
            const right = cell.endsWith(':');
            if (left && right) return 'center';
            if (right) return 'right';
            return left ? 'left' : '';
        });
    }

    function renderTable(headerLine, separatorLine, rows) {
        const headers = splitTableRow(headerLine);
        const alignments = tableAlignment(separatorLine);
        const headerHtml = headers.map((cell, index) => {
            const align = alignments[index]
                ? ` style="text-align:${alignments[index]}"`
                : '';
            return `<th${align}>${inlineMarkdown(cell)}</th>`;
        }).join('');
        const bodyHtml = rows.map(row => {
            const cells = splitTableRow(row);
            return `<tr>${headers.map((_header, index) => {
                const align = alignments[index]
                    ? ` style="text-align:${alignments[index]}"`
                    : '';
                return `<td${align}>${inlineMarkdown(cells[index] || '')}</td>`;
            }).join('')}</tr>`;
        }).join('');
        return `
            <div class="agent-table-wrap">
                <table class="agent-table">
                    <thead><tr>${headerHtml}</tr></thead>
                    <tbody>${bodyHtml}</tbody>
                </table>
            </div>`;
    }

    function isSpecialBlock(line) {
        const trimmed = String(line || '').trim();
        return (
            /^```/.test(trimmed)
            || /^#{1,6}\s+/.test(trimmed)
            || /^>\s?/.test(trimmed)
            || /^[-*+]\s+/.test(trimmed)
            || /^\d+\.\s+/.test(trimmed)
            || /^---+$/.test(trimmed)
        );
    }

    function renderMarkdown(text) {
        const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
        const html = [];
        let index = 0;
        while (index < lines.length) {
            const line = lines[index];
            const trimmed = line.trim();
            if (!trimmed) {
                index += 1;
                continue;
            }

            const fence = trimmed.match(/^```([A-Za-z0-9_+.-]*)\s*$/);
            if (fence) {
                index += 1;
                const codeLines = [];
                while (
                    index < lines.length
                    && !/^```/.test(lines[index].trim())
                ) {
                    codeLines.push(lines[index]);
                    index += 1;
                }
                if (index < lines.length) index += 1;
                const language = fence[1]
                    ? ` data-language="${escapeHtml(fence[1])}"`
                    : '';
                html.push(
                    `<pre class="agent-code"${language}><code>`
                    + `${escapeHtml(codeLines.join('\n'))}</code></pre>`,
                );
                continue;
            }

            if (
                line.includes('|')
                && index + 1 < lines.length
                && isTableSeparator(lines[index + 1])
            ) {
                const rows = [];
                index += 2;
                while (
                    index < lines.length
                    && lines[index].includes('|')
                    && lines[index].trim()
                ) {
                    rows.push(lines[index]);
                    index += 1;
                }
                html.push(renderTable(line, lines[index - rows.length - 1], rows));
                continue;
            }

            const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
            if (heading) {
                const level = heading[1].length;
                html.push(
                    `<h${level}>${inlineMarkdown(heading[2])}</h${level}>`,
                );
                index += 1;
                continue;
            }

            if (/^---+$/.test(trimmed)) {
                html.push('<hr>');
                index += 1;
                continue;
            }

            if (/^>\s?/.test(trimmed)) {
                const quote = [];
                while (
                    index < lines.length
                    && /^>\s?/.test(lines[index].trim())
                ) {
                    quote.push(lines[index].trim().replace(/^>\s?/, ''));
                    index += 1;
                }
                html.push(
                    `<blockquote>${quote.map(inlineMarkdown).join('<br>')}</blockquote>`,
                );
                continue;
            }

            if (/^[-*+]\s+/.test(trimmed)) {
                const items = [];
                while (
                    index < lines.length
                    && /^[-*+]\s+/.test(lines[index].trim())
                ) {
                    items.push(
                        lines[index].trim().replace(/^[-*+]\s+/, ''),
                    );
                    index += 1;
                }
                html.push(
                    `<ul>${items.map(item =>
                        `<li>${inlineMarkdown(item)}</li>`
                    ).join('')}</ul>`,
                );
                continue;
            }

            if (/^\d+\.\s+/.test(trimmed)) {
                const items = [];
                while (
                    index < lines.length
                    && /^\d+\.\s+/.test(lines[index].trim())
                ) {
                    items.push(
                        lines[index].trim().replace(/^\d+\.\s+/, ''),
                    );
                    index += 1;
                }
                html.push(
                    `<ol>${items.map(item =>
                        `<li>${inlineMarkdown(item)}</li>`
                    ).join('')}</ol>`,
                );
                continue;
            }

            const paragraph = [];
            while (
                index < lines.length
                && lines[index].trim()
                && !isSpecialBlock(lines[index])
                && !(
                    lines[index].includes('|')
                    && index + 1 < lines.length
                    && isTableSeparator(lines[index + 1])
                )
            ) {
                paragraph.push(lines[index].trim());
                index += 1;
            }
            if (paragraph.length) {
                html.push(
                    `<p>${paragraph.map(inlineMarkdown).join('<br>')}</p>`,
                );
            } else {
                html.push(`<p>${inlineMarkdown(trimmed)}</p>`);
                index += 1;
            }
        }
        return `<div class="agent-rendered agent-markdown">${html.join('')}</div>`;
    }

    function renderStructured(value) {
        return (
            '<div class="agent-rendered agent-structured">'
            + `<pre class="agent-code"><code>${escapeHtml(asText(value))}</code></pre>`
            + '</div>'
        );
    }

    function render(value) {
        if (value == null || value === '') return '';
        if (typeof value !== 'string') return renderStructured(value);
        const text = value.replace(/\r\n?/g, '\n');
        const parsedJson = tryParseJson(text);
        if (parsedJson !== null) return renderStructured(parsedJson);
        return renderMarkdown(text);
    }

    function summarize(value, limit = 180) {
        if (value == null || value === '') return '';
        if (typeof value !== 'string') {
            const text = asText(value).replace(/\s+/g, ' ').trim();
            return truncate(text, limit);
        }
        const lines = value.replace(/\r\n?/g, '\n').split('\n');
        for (let index = 0; index < lines.length - 1; index += 1) {
            if (lines[index].includes('|') && isTableSeparator(lines[index + 1])) {
                const headers = splitTableRow(lines[index]);
                let rows = 0;
                let cursor = index + 2;
                while (
                    cursor < lines.length
                    && lines[cursor].includes('|')
                    && lines[cursor].trim()
                ) {
                    rows += 1;
                    cursor += 1;
                }
                return `Markdown 表格 · ${rows} 行 × ${headers.length} 列 · `
                    + headers.join(' / ');
            }
        }
        const plain = value
            .replace(/```[A-Za-z0-9_+.-]*\n?/g, '')
            .replace(/[#>*_`~|]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
        return truncate(plain, limit);
    }

    function truncate(text, limit) {
        const value = String(text || '');
        return value.length > limit
            ? `${value.slice(0, limit)}…`
            : value;
    }

    return {
        render,
        summarize,
        escapeHtml,
        plainText: asText,
    };
})();

window.AgentTraceContent = AgentTraceContent;
