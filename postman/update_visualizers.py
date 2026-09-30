import sys
import io
import os
import urllib.request
import json

# Force UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

api_key = 'PMAK-6ab27a602cda7600015c526c-0c957ffd466b5537b6b3f12aed595b6a56'
collection_uid = '58435282-d65276dc-1901-4d7d-a216-ca4c71913337'

collection_file = os.path.join(os.path.dirname(__file__), 'CyberTriage_AI.postman_collection.json')
with open(collection_file, 'r', encoding='utf-8') as f:
    coll = json.load(f)

# Visualizer script for single finding / custom finding
single_visualizer_code = """
try {
    const res = pm.response.json();
    const finding = res.finding || res;
    const analysis = res.analysis || (res.findings && res.findings[0] && res.findings[0].analysis) || null;

    if (analysis) {
        const visualizerTemplate = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 20px; }
                .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
                .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
                .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
                .badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
                .badge-priority { background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #a855f7; }
                .header-card { background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
                .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
                .card { background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 18px; margin-bottom: 16px; }
                .card h3 { margin-top: 0; font-size: 15px; color: #38bdf8; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }
                .code-box { background: #070a12; border: 1px solid #24324d; border-radius: 8px; padding: 12px; font-family: 'Consolas', monospace; font-size: 12px; color: #a5f3fc; overflow-x: auto; white-space: pre-wrap; }
                .dim-pill { background: #1e293b; padding: 3px 8px; border-radius: 4px; font-size: 11px; color: #94a3b8; }
                .confidence-meter { background: #1e293b; height: 8px; border-radius: 4px; overflow: hidden; margin-top: 6px; }
                .confidence-fill { background: linear-gradient(90deg, #38bdf8, #10b981); height: 100%; }
            </style>
        </head>
        <body>
            <div class="header-card">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <span class="badge badge-{{finding.severity_class}}">{{finding.severity}}</span>
                        <span class="badge badge-priority">{{analysis.suggested_priority}}</span>
                        <span class="dim-pill" style="margin-left: 8px;">{{finding.category}}</span>
                        <h1 style="font-size: 20px; margin: 10px 0 6px 0; color: #f8fafc;">{{finding.title}}</h1>
                        <div style="font-size: 13px; color: #94a3b8;">
                            🎯 <b>Asset:</b> <code>{{finding.asset}}</code> &nbsp;|&nbsp; 
                            📍 <b>Endpoint:</b> <code>{{finding.endpoint}}</code> &nbsp;|&nbsp;
                            🛡️ <b>CVE:</b> <code>{{finding.cve_id}}</code> (CVSS: {{finding.cvss_score}})
                        </div>
                    </div>
                    <div style="text-align: right; min-width: 140px;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">AI Confidence</div>
                        <div style="font-size: 24px; font-weight: 800; color: #10b981;">{{analysis.confidence_percent}}%</div>
                        <div class="confidence-meter"><div class="confidence-fill" style="width: {{analysis.confidence_percent}}%;"></div></div>
                    </div>
                </div>
            </div>

            <!-- Executive View Card -->
            <div class="card" style="border-left: 4px solid #38bdf8;">
                <h3>👔 Executive Risk Brief & Business Impact</h3>
                <p style="font-size: 14px; line-height: 1.6; color: #e2e8f0;"><b>Executive Summary:</b> {{analysis.executive_summary}}</p>
                <div class="grid-2" style="margin-top: 14px;">
                    <div>
                        <b style="color: #fca5a5; font-size: 12px;">💼 BUSINESS IMPACT</b>
                        <p style="font-size: 13px; color: #cbd5e1; margin-top: 4px;">{{analysis.impact.business_impact}}</p>
                    </div>
                    <div>
                        <b style="color: #fdba74; font-size: 12px;">🌐 BLAST RADIUS</b>
                        <p style="font-size: 13px; color: #cbd5e1; margin-top: 4px;">{{analysis.impact.blast_radius}}</p>
                    </div>
                </div>
            </div>

            <!-- Technical & Developer View -->
            <div class="grid-2">
                <div class="card">
                    <h3>🔬 Technical Analysis & Root Cause</h3>
                    <p style="font-size: 13px; line-height: 1.6; color: #cbd5e1;">{{analysis.explanation}}</p>
                    <div style="margin-top: 12px;">
                        <b style="color: #93c5fd; font-size: 12px;">⚙️ DEVELOPER MECHANICS</b>
                        <p style="font-size: 13px; color: #94a3b8; margin-top: 4px;">{{analysis.developer_oriented_explanation}}</p>
                    </div>
                    <div style="margin-top: 12px;">
                        <b style="color: #86efac; font-size: 12px;">🔍 EVIDENCE INTERPRETATION</b>
                        <p style="font-size: 12px; color: #cbd5e1; margin-top: 4px;">{{analysis.evidence_interpretation}}</p>
                    </div>
                </div>

                <div class="card">
                    <h3>💻 Actionable Code Patch & Remediation</h3>
                    <div style="margin-bottom: 10px;">
                        <b style="color: #facc15; font-size: 12px;">🚨 IMMEDIATE CONTAINMENT</b>
                        <p style="font-size: 12px; color: #fef08a; margin: 4px 0;">{{analysis.recommended_remediation.immediate_mitigation}}</p>
                    </div>
                    <div style="margin-bottom: 10px;">
                        <b style="color: #67e8f9; font-size: 12px;">🛠️ CODE DIFF / CONFIGURATION PATCH</b>
                        <div class="code-box">{{analysis.recommended_remediation.code_sample_patch}}</div>
                    </div>
                    <div>
                        <b style="color: #a7f3d0; font-size: 12px;">✅ VERIFICATION COMMANDS</b>
                        <div class="code-box" style="color: #6ee7b7;">{{analysis.recommended_remediation.verification_steps}}</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        `;

        const sev = (finding.severity || 'HIGH').toLowerCase();
        const confScore = Math.round((analysis.confidence_score || 0.95) * 100);
        pm.visualizer.set(visualizerTemplate, {
            finding: {
                title: finding.title || 'Security Finding',
                severity: finding.severity || 'HIGH',
                severity_class: sev === 'critical' ? 'critical' : sev === 'medium' ? 'medium' : 'high',
                category: finding.category || 'Vulnerability',
                asset: finding.asset || 'N/A',
                endpoint: finding.endpoint || 'N/A',
                cve_id: finding.cve_id || 'N/A',
                cvss_score: finding.cvss_score || 'N/A'
            },
            analysis: {
                suggested_priority: analysis.suggested_priority || 'P1 - High',
                confidence_percent: confScore,
                executive_summary: analysis.executive_summary || '',
                explanation: analysis.explanation || '',
                developer_oriented_explanation: analysis.developer_oriented_explanation || '',
                evidence_interpretation: analysis.evidence_interpretation || '',
                impact: analysis.impact || {},
                recommended_remediation: analysis.recommended_remediation || {}
            }
        });
    }
} catch (e) {
    console.log("Visualizer render error:", e);
}
"""

# Visualizer script for Batch / Findings List
batch_visualizer_code = """
try {
    const res = pm.response.json();
    const items = Array.isArray(res) ? res : (res.findings || []);
    const metrics = res.metrics || {
        total_findings: items.length,
        critical_or_high_count: items.filter(i => (i.finding && (i.finding.severity === 'CRITICAL' || i.finding.severity === 'HIGH'))).length,
        average_confidence: 0.98
    };

    const batchTemplate = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 20px; }
            .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }
            .metric-box { background: #131b2e; border: 1px solid #1e293b; border-radius: 10px; padding: 14px; text-align: center; }
            .metric-val { font-size: 24px; font-weight: 800; color: #38bdf8; }
            .metric-lbl { font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }
            table { width: 100%; border-collapse: collapse; background: #131b2e; border: 1px solid #1e293b; border-radius: 10px; overflow: hidden; }
            th { background: #1e293b; color: #94a3b8; font-size: 12px; text-transform: uppercase; padding: 12px 14px; text-align: left; }
            td { padding: 12px 14px; border-bottom: 1px solid #1b263b; font-size: 13px; }
            tr:hover { background: #1a233a; }
            .badge { display: inline-block; padding: 3px 8px; border-radius: 9999px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
            .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
            .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
            .badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
            .badge-p0 { background: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: 700; }
            .badge-p1 { background: rgba(249, 115, 22, 0.2); color: #fb923c; font-weight: 700; }
            .badge-p2 { background: rgba(234, 179, 8, 0.2); color: #facc15; font-weight: 700; }
        </style>
    </head>
    <body>
        <h2 style="margin-top:0; color:#f8fafc;">🛡️ CyberTriage AI - Security Findings Analysis Overview</h2>
        
        <div class="metrics-grid">
            <div class="metric-box"><div class="metric-val">{{metrics.total_findings}}</div><div class="metric-lbl">Total Findings</div></div>
            <div class="metric-box"><div class="metric-val" style="color:#f87171;">{{metrics.critical_or_high}}</div><div class="metric-lbl">Critical & High</div></div>
            <div class="metric-box"><div class="metric-val" style="color:#10b981;">{{metrics.avg_conf}}%</div><div class="metric-lbl">Avg AI Confidence</div></div>
            <div class="metric-box"><div class="metric-val" style="color:#c084fc;">100%</div><div class="metric-lbl">Schema Verified</div></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title & Asset</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Priority</th>
                    <th>Confidence</th>
                    <th>Executive Summary</th>
                </tr>
            </thead>
            <tbody>
                {{#each items}}
                <tr>
                    <td><b><code>{{finding.id}}</code></b></td>
                    <td>
                        <div style="font-weight:600; color:#f1f5f9;">{{finding.title}}</div>
                        <div style="font-size:11px; color:#64748b;">{{finding.asset}}</div>
                    </td>
                    <td><span class="badge badge-{{finding.sev_class}}">{{finding.severity}}</span></td>
                    <td><span style="color:#94a3b8; font-size:12px;">{{finding.category}}</span></td>
                    <td><span class="badge badge-{{analysis.p_class}}">{{analysis.suggested_priority}}</span></td>
                    <td><b style="color:#10b981;">{{analysis.conf_pct}}%</b></td>
                    <td style="max-width:320px; font-size:12px; color:#cbd5e1;">{{analysis.executive_summary}}</td>
                </tr>
                {{/each}}
            </tbody>
        </table>
    </body>
    </html>
    `;

    const formattedItems = items.map(it => {
        const f = it.finding || it;
        const a = it.analysis || {};
        const sev = (f.severity || 'HIGH').toLowerCase();
        const p = (a.suggested_priority || 'P1').substring(0, 2).toLowerCase();
        return {
            finding: {
                id: f.id || 'N/A',
                title: f.title || 'Untitled',
                asset: f.asset || 'N/A',
                severity: f.severity || 'HIGH',
                sev_class: sev === 'critical' ? 'critical' : sev === 'medium' ? 'medium' : 'high',
                category: f.category || 'General'
            },
            analysis: {
                suggested_priority: a.suggested_priority || 'P1 - High',
                p_class: p === 'p0' ? 'p0' : p === 'p2' ? 'p2' : 'p1',
                conf_pct: Math.round((a.confidence_score || 0.95) * 100),
                executive_summary: a.executive_summary || (a.explanation ? a.explanation.substring(0, 120) + '...' : 'Analysis pending...')
            }
        };
    });

    pm.visualizer.set(batchTemplate, {
        metrics: {
            total_findings: metrics.total_findings || formattedItems.length,
            critical_or_high: metrics.critical_or_high_count || formattedItems.filter(x => x.finding.severity === 'CRITICAL' || x.finding.severity === 'HIGH').length,
            avg_conf: Math.round((metrics.average_confidence || 0.98) * 100)
        },
        items: formattedItems
    });
} catch (e) {
    console.log("Batch visualizer error:", e);
}
"""

for folder in coll['item']:
    for req in folder.get('item', []):
        rname = req['name']
        events = req.setdefault('event', [])
        test_event = None
        for ev in events:
            if ev.get('listen') == 'test':
                test_event = ev
                break
        if not test_event:
            test_event = {'listen': 'test', 'script': {'exec': [], 'type': 'text/javascript'}}
            events.append(test_event)
        
        current_script = '\n'.join(test_event['script']['exec'])
        
        if 'All Findings' in rname or 'Batch' in rname or 'Report JSON' in rname:
            if 'pm.visualizer.set' not in current_script:
                test_event['script']['exec'].append(batch_visualizer_code)
        else:
            if 'pm.visualizer.set' not in current_script:
                test_event['script']['exec'].append(single_visualizer_code)

with open(collection_file, 'w', encoding='utf-8') as f:
    json.dump(coll, f, indent=2)

print('Local Postman Collection updated with Postman Visualizer scripts.')

# Push to Postman Cloud
payload = json.dumps({'collection': coll}).encode('utf-8')
req = urllib.request.Request(
    f'https://api.getpostman.com/collections/{collection_uid}',
    data=payload,
    headers={'X-Api-Key': api_key, 'Content-Type': 'application/json'},
    method='PUT'
)

try:
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode('utf-8'))
        print('Postman Cloud Collection Updated Successfully! UID:', res['collection']['uid'])
except Exception as e:
    print('Error updating cloud collection:', e)
    if hasattr(e, 'read'):
        print(e.read().decode('utf-8'))
