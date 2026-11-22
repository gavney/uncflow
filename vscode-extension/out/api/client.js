"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.UncflowClient = void 0;
const vscode = __importStar(require("vscode"));
class UncflowClient {
    context;
    authToken = '';
    constructor(context) {
        this.context = context;
    }
    async loadAuthToken() {
        this.authToken = (await this.context?.secrets.get('uncflow.authToken')) || '';
    }
    async setAuthToken(token) {
        this.authToken = token;
        if (this.context) {
            if (token) {
                await this.context.secrets.store('uncflow.authToken', token);
            }
            else {
                await this.context.secrets.delete('uncflow.authToken');
            }
        }
    }
    getServerUrl() {
        const config = vscode.workspace.getConfiguration('uncflow');
        const rawUrl = config.get('serverUrl', 'https://uncflow.duckdns.org');
        return rawUrl.trim().replace(/\/+$/, '');
    }
    getAuthHeaders() {
        const config = vscode.workspace.getConfiguration('uncflow');
        const token = (this.authToken || config.get('apiToken', '')).trim();
        const headers = {};
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
            headers['X-CI-Token'] = token;
        }
        return headers;
    }
    isLocalHost() {
        const url = this.getServerUrl().toLowerCase();
        return (url.includes('localhost') ||
            url.includes('127.0.0.1') ||
            url.includes('0.0.0.0'));
    }
    async getTemplates() {
        const serverUrl = this.getServerUrl();
        const url = `${serverUrl}/api/templates`;
        const res = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                ...this.getAuthHeaders()
            }
        });
        if (!res.ok) {
            throw new Error(`Не удалось загрузить шаблоны сценариев (${res.status} ${res.statusText})`);
        }
        const data = await res.json();
        return data.map(item => ({
            id: item.id,
            title: item.title || item.name || item.id,
            category: item.category || 'Security',
            description: item.description || '',
            graph: item.graph
        }));
    }
    async uploadArchive(zipBuffer, filename = 'project.zip') {
        const serverUrl = this.getServerUrl();
        const url = `${serverUrl}/api/sources/local-archive`;
        const blob = new Blob([zipBuffer], { type: 'application/zip' });
        const formData = new FormData();
        formData.append('archive', blob, filename);
        const headers = { ...this.getAuthHeaders() };
        const res = await fetch(url, {
            method: 'POST',
            headers,
            body: formData
        });
        if (!res.ok) {
            const errText = await res.text();
            let msg = errText;
            try {
                const parsed = JSON.parse(errText);
                if (parsed.error)
                    msg = parsed.error;
            }
            catch {
                // use raw text
            }
            throw new Error(`Ошибка загрузки архива проекта на ${serverUrl}: ${msg}`);
        }
        const data = await res.json();
        if (typeof data.path !== 'string' ||
            !data.path.trim() ||
            typeof data.fileCount !== 'number' ||
            !Number.isInteger(data.fileCount) ||
            data.fileCount < 1) {
            throw new Error(`Сервер принял ZIP-архив на ${serverUrl}, но вернул некорректный путь проекта или число файлов.`);
        }
        return { path: data.path, fileCount: data.fileCount };
    }
    async runAudit(scenarioId, params) {
        const serverUrl = this.getServerUrl();
        if (params.repository || params.codePath) {
            const templates = await this.getTemplates();
            const template = templates.find(item => item.id === scenarioId) ||
                templates.find(item => item.id === 'template-full-audit');
            if (!template?.graph) {
                throw new Error('Не удалось получить сценарий для Git-аудита');
            }
            const graph = JSON.parse(JSON.stringify(template.graph));
            for (const node of graph.nodes || []) {
                if (params.codePath && ['source.local', 'source.archive', 'source.git'].includes(node.type)) {
                    node.type = 'source.local';
                    node.settings = {
                        ...(node.settings || {}),
                        path: params.codePath
                    };
                }
                else if (params.repository && (node.type === 'source.local' || node.type === 'source.archive')) {
                    node.type = 'source.git';
                    node.settings = {
                        ...(node.settings || {}),
                        repoUrl: params.repository,
                        branch: params.branch || 'main',
                        subDir: '',
                        depth: 1
                    };
                }
            }
            const res = await fetch(`${serverUrl}/api/workflow/run`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    ...this.getAuthHeaders()
                },
                body: JSON.stringify({ graph, initialData: {} })
            });
            if (!res.ok) {
                const text = await res.text();
                throw new Error(`Ошибка запуска Git-аудита (${res.status}): ${text}`);
            }
            const run = await res.json();
            if (run.success === false) {
                const failures = Object.entries(run.errors || {})
                    .map(([nodeId, error]) => `${nodeId}: ${String(error)}`)
                    .join('; ');
                throw new Error(`Проверка не завершилась${failures ? `: ${failures}` : '.'}`);
            }
            const outputs = run.nodeOutputs || {};
            const reportAndAggregatorNodes = graph.nodes.filter((node) => ['report.dual', 'report.json', 'scanner.aggregator', 'scan.aggregator'].includes(node.type));
            let findings = [];
            for (const node of reportAndAggregatorNodes) {
                const output = outputs[node.id];
                const nodeFindings = Array.isArray(output?.allFindings) && output.allFindings.length > 0
                    ? output.allFindings
                    : output?.findings;
                if (Array.isArray(nodeFindings) && nodeFindings.length > 0) {
                    findings = nodeFindings;
                    break;
                }
            }
            if (findings.length === 0) {
                const scannerTypes = ['scanner.sast', 'scan.sast', 'scanner.secrets', 'scan.secret', 'scanner.sca', 'scan.sca'];
                findings = graph.nodes
                    .filter((node) => scannerTypes.includes(node.type))
                    .flatMap((node) => Array.isArray(outputs[node.id]?.findings) ? outputs[node.id].findings : []);
            }
            const summary = {
                critical: findings.filter(f => f.severity === 'CRITICAL').length,
                high: findings.filter(f => f.severity === 'HIGH').length,
                medium: findings.filter(f => f.severity === 'MEDIUM').length,
                low: findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length,
                total: findings.length
            };
            return {
                status: run.success ? 'passed' : 'failed',
                exitCode: run.success ? 0 : 1,
                summary,
                reportUrl: `${serverUrl}/api/reports/latest`,
                findings,
                totalFindings: findings.length
            };
        }
        const url = `${serverUrl}/api/ci/run`;
        const bodyPayload = {
            workflowId: scenarioId,
            failOnCritical: false
        };
        if (params.codePath) {
            bodyPayload.codePath = params.codePath;
        }
        else if (params.repository) {
            bodyPayload.repository = params.repository;
        }
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...this.getAuthHeaders()
            },
            body: JSON.stringify(bodyPayload)
        });
        if (!res.ok) {
            const errText = await res.text();
            let msg = errText;
            try {
                const parsed = JSON.parse(errText);
                if (parsed.error)
                    msg = parsed.error;
            }
            catch {
                // use raw
            }
            throw new Error(`Ошибка выполнения аудита на ${serverUrl}: ${msg}`);
        }
        const data = await res.json();
        const rawFindings = (data.findings ||
            data.jsonReport?.findings ||
            []);
        const summary = data.summary || {
            critical: data.criticalCount || 0,
            high: data.highCount || 0,
            medium: data.mediumCount || 0,
            low: data.lowCount || 0,
            total: data.totalFindings || rawFindings.length
        };
        return {
            status: data.status || 'passed',
            exitCode: data.exitCode || 0,
            summary,
            reportUrl: data.reportUrl,
            findings: rawFindings,
            totalFindings: summary.total
        };
    }
}
exports.UncflowClient = UncflowClient;
//# sourceMappingURL=client.js.map