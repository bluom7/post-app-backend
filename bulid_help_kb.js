// Usage: node build_help_kb.js path/to/index.html path/to/help_kb.json
// Reads the Help Center articles straight out of index.html and writes the
// knowledge base that BluOm AI support assistant answers from.
// Re-run this whenever you add/edit Help Center articles.
const fs = require('fs');
const html = fs.readFileSync(process.argv[2] || 'index.html', 'utf8');
const start = html.indexOf('var managingAccSections');
const end = html.indexOf('function helpBlocksText');
if (start < 0 || end < 0) { console.error('Could not find article data in index.html'); process.exit(1); }
const body = html.slice(start, end) + '\nreturn {managingAccSections,safetySections,rulesSections,usingSections};';
const m = new Function(body)();

function blocksText(blocks) {
  return (blocks || []).map(function (b) {
    var t = '## ' + (b.heading || '');
    (b.paragraphs || []).forEach(function (p) { t += '\n' + p; });
    (b.bullets || []).forEach(function (p) { t += '\n- ' + p; });
    (b.steps || []).forEach(function (p, i) { t += '\n' + (i + 1) + '. ' + p; });
    return t;
  }).join('\n');
}
const out = [];
[['usingSections', 'using'], ['safetySections', 'safety'], ['rulesSections', 'rules']].forEach(function (pair) {
  m[pair[0]].forEach(function (sec) {
    sec.articles.forEach(function (a) {
      out.push({ kind: pair[1], sectionKey: sec.key, category: sec.title, title: a.title, summary: a.summary || '', text: blocksText(a.blocks) });
    });
  });
});
m.managingAccSections.forEach(function (sec) {
  var text = (sec.guide || []).map(function (g) {
    var s = '## ' + g.heading;
    (g.steps || []).forEach(function (p, i) { s += '\n' + (i + 1) + '. ' + p; });
    if (g.note) s += '\nNote: ' + g.note;
    return s;
  }).join('\n');
  out.push({ kind: 'manage', key: sec.key, category: 'Managing your account', title: sec.title,
    summary: (sec.guide || []).map(function (g) { return g.heading; }).join(' · '), text: text });
});
fs.writeFileSync(process.argv[3] || 'help_kb.json', JSON.stringify(out));
console.log('Wrote ' + out.length + ' articles');
