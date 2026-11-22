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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const client_1 = require("./api/client");
const diagnostics_1 = require("./providers/diagnostics");
const findingsTree_1 = require("./providers/findingsTree");
const detailsView_1 = require("./providers/detailsView");
const quickFix_1 = require("./providers/quickFix");
const workspace_1 = require("./state/workspace");
const archiver_1 = require("./utils/archiver");
const child_process_1 = require("child_process");
const util_1 = require("util");
let statusBarItem;
const diagnosticsManager = new diagnostics_1.DiagnosticsManager();
const workspaceState = workspace_1.WorkspaceState.getInstance();
let client;
const execFileAsync = (0, util_1.promisify)(child_process_1.execFile);
async function getGitRemote(folderPath) {
    try {
        const { stdout: urlOut } = await execFileAsync('git', ['config', '--get', 'remote.origin.url'], { cwd: folderPath });
        const url = urlOut.trim();
        if (!url)
            return undefined;
        const { stdout: branchOut } = await execFileAsync('git', ['branch', '--show-current'], { cwd: folderPath });
        return { url, branch: branchOut.trim() || 'main' };
    }
    catch {
        return undefined;
    }
}
async function loginToServer() {
    const email = await vscode.window.showInputBox({
        prompt: 'Email для входа в uncflow',
        ignoreFocusOut: true
    });
    if (!email)
        return false;
    const password = await vscode.window.showInputBox({
        prompt: 'Пароль',
        password: true,
        ignoreFocusOut: true
    });
    if (!password)
        return false;
    try {
        const serverUrl = vscode.workspace.getConfiguration('uncflow')
            .get('serverUrl', 'https://uncflow.duckdns.org')
            .trim()
            .replace(/\/+$/, '');
        const response = await fetch(`${serverUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email.trim(), password })
        });
        const data = await response.json();
        if (!response.ok || !data.token) {
            throw new Error(data.error || `HTTP ${response.status}`);
        }
        await client.setAuthToken(data.token);
        void vscode.window.showInformationMessage(`uncflow: выполнен вход как ${data.user?.name || email}`);
        return true;
    }
    catch (err) {
        void vscode.window.showErrorMessage(`Ошибка входа uncflow: ${err.message}`);
        return false;
    }
}
function activate(context) {
    workspaceState.init(context);
    client = new client_1.UncflowClient(context);
    void client.loadAuthToken();
    // 1. Status Bar widget
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'uncflow.runLastScenario';
    updateStatusBar('idle');
    statusBarItem.show();
    // 2. Register TreeDataProvider & Webview View
    const treeProvider = new findingsTree_1.FindingsTreeProvider();
    vscode.window.registerTreeDataProvider('uncflow.views.findings', treeProvider);
    const detailsProvider = new detailsView_1.DetailsViewProvider(context.extensionUri);
    context.subscriptions.push(vscode.window.registerWebviewViewProvider('uncflow.views.details', detailsProvider));
    // 3. Register CodeActionProvider (QuickFix)
    const quickFixProvider = new quickFix_1.UncflowQuickFixProvider();
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, quickFixProvider, { providedCodeActionKinds: quickFix_1.UncflowQuickFixProvider.providedCodeActionKinds }));
    // 4. Register Command: Run Last Scenario
    const runLastCmd = vscode.commands.registerCommand('uncflow.runLastScenario', async () => {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || folders.length === 0) {
            vscode.window.showWarningMessage('Откройте папку проекта для запуска аудита uncflow.');
            return;
        }
        const currentFolder = folders[0].uri.fsPath;
        await executeAudit(currentFolder, workspaceState.lastScenarioId, workspaceState.lastScenarioTitle);
    });
    // 5. Register Command: Select Scenario and Run
    const selectCmd = vscode.commands.registerCommand('uncflow.selectAndRunScenario', async () => {
        try {
            const templates = await client.getTemplates();
            workspaceState.setTemplates(templates);
            const items = templates.map(t => ({
                label: t.title,
                description: t.category,
                detail: t.description,
                id: t.id
            }));
            // Add quick actions
            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Выберите сценарий аудита безопасности uncflow'
            });
            if (selected) {
                await workspaceState.setLastScenario(selected.id, selected.label);
                const folders = vscode.workspace.workspaceFolders;
                if (folders && folders.length > 0) {
                    await executeAudit(folders[0].uri.fsPath, selected.id, selected.label);
                }
            }
        }
        catch (err) {
            vscode.window.showErrorMessage(`Не удалось получить сценарии с uncflow: ${err.message}`);
        }
    });
    // 6. Register Command: Scan Current File
    const scanFileCmd = vscode.commands.registerCommand('uncflow.scanCurrentFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('Откройте файл для проверки.');
            return;
        }
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || folders.length === 0) {
            vscode.window.showWarningMessage('Откройте проект в рабочей области.');
            return;
        }
        await executeAudit(folders[0].uri.fsPath, workspaceState.lastScenarioId, `Файл: ${editor.document.fileName}`);
    });
    // 7. Register Command: Open uncflow Dashboard
    const openDashboardCmd = vscode.commands.registerCommand('uncflow.openDashboard', () => {
        const config = vscode.workspace.getConfiguration('uncflow');
        const url = config.get('serverUrl', 'https://uncflow.duckdns.org');
        vscode.env.openExternal(vscode.Uri.parse(url));
    });
    // 8. Register Command: Settings
    const openSettingsCmd = vscode.commands.registerCommand('uncflow.openSettings', () => {
        vscode.commands.executeCommand('workbench.action.openSettings', 'uncflow');
    });
    const loginCmd = vscode.commands.registerCommand('uncflow.login', async () => {
        await loginToServer();
    });
    const logoutCmd = vscode.commands.registerCommand('uncflow.logout', async () => {
        await client.setAuthToken('');
        vscode.window.showInformationMessage('uncflow: сеанс завершён');
    });
    // 9. Register Command: Clear Findings
    const clearCmd = vscode.commands.registerCommand('uncflow.clearFindings', () => {
        diagnosticsManager.clear();
        workspaceState.clearFindings();
        updateStatusBar('idle');
        vscode.window.showInformationMessage('uncflow: Результаты проверки очищены.');
    });
    // 10. Register Command: Refresh Tree
    const refreshTreeCmd = vscode.commands.registerCommand('uncflow.refreshTree', () => {
        treeProvider.refresh();
    });
    // 11. Register Command: Show Finding Details
    const showDetailsCmd = vscode.commands.registerCommand('uncflow.showFindingDetails', (finding) => {
        workspaceState.setSelectedFinding(finding);
        vscode.commands.executeCommand('uncflow.views.details.focus');
    });
    // 12. Run on Save listener
    const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (doc) => {
        const config = vscode.workspace.getConfiguration('uncflow');
        const runOnSave = config.get('runOnSave', false);
        if (!runOnSave)
            return;
        const folders = vscode.workspace.workspaceFolders;
        if (folders && folders.length > 0) {
            await executeAudit(folders[0].uri.fsPath, workspaceState.lastScenarioId, workspaceState.lastScenarioTitle);
        }
    });
    context.subscriptions.push(statusBarItem, diagnosticsManager, runLastCmd, selectCmd, scanFileCmd, openDashboardCmd, openSettingsCmd, loginCmd, logoutCmd, clearCmd, refreshTreeCmd, showDetailsCmd, onSaveListener);
}
async function executeAudit(folderPath, scenarioId, scenarioTitle) {
    await client.loadAuthToken();
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'uncflow Security Platform',
        cancellable: false
    }, async (progress) => {
        updateStatusBar('running');
        progress.report({ message: 'Подготовка к аудиту проекта...' });
        try {
            let codePath = folderPath;
            const isLocal = client.isLocalHost();
            if (!isLocal) {
                progress.report({ message: 'Упаковка проекта в безопасный ZIP-архив...' });
                try {
                    const zipBuffer = await (0, archiver_1.createProjectZipBuffer)(folderPath);
                    progress.report({ message: 'Передача ZIP-архива на сервер uncflow...' });
                    const uploadRes = await client.uploadArchive(zipBuffer, 'vscode-project.zip');
                    codePath = uploadRes.path;
                }
                catch (uploadError) {
                    if (!/Not found|404/i.test(uploadError.message))
                        throw uploadError;
                    const remote = await getGitRemote(folderPath);
                    if (!remote) {
                        throw new Error('Сервер не поддерживает /api/sources/local-archive. Откройте проект как Git-репозиторий с настроенным origin или обновите backend на сервере.');
                    }
                    progress.report({ message: 'Сервер не принимает ZIP: запуск проверки Git origin...' });
                    vscode.window.showWarningMessage('На удалённом сервере недоступна загрузка ZIP. Будет проанализирована версия из Git origin, без несохранённых локальных изменений.');
                    codePath = '';
                    global.__uncflowRepository = remote;
                }
            }
            progress.report({ message: `Выполнение сценария "${scenarioTitle}"...` });
            const repository = global.__uncflowRepository;
            delete global.__uncflowRepository;
            const runParams = {
                codePath: codePath || undefined,
                repository: repository?.url,
                branch: repository?.branch
            };
            let result;
            try {
                result = await client.runAudit(scenarioId, runParams);
            }
            catch (err) {
                if (!/Неверный или отсутствующий токен авторизации CI|401|unauthorized/i.test(err.message)) {
                    throw err;
                }
                const loginAction = 'Войти в uncflow';
                const action = await vscode.window.showErrorMessage('Для аудита на сервере требуется авторизация. Войдите в uncflow, чтобы продолжить.', loginAction);
                if (action !== loginAction || !(await loginToServer()))
                    return;
                result = await client.runAudit(scenarioId, runParams);
            }
            // Apply findings to editor squiggles and problems panel
            diagnosticsManager.applyFindings(result.findings || [], folderPath);
            // Update state for tree view and detail cards
            workspaceState.setFindings(result.findings || [], result.summary);
            const { critical, high, total } = result.summary || { critical: 0, high: 0, total: 0 };
            updateStatusBar('completed', result.summary);
            if (critical > 0 || high > 0) {
                const btnView = 'Показать проблемы';
                const btnWeb = 'Открыть в Web';
                const choice = await vscode.window.showErrorMessage(`uncflow: Обнаружено ${total} проблем безопасности (${critical} Critical, ${high} High)!`, btnView, btnWeb);
                if (choice === btnView) {
                    vscode.commands.executeCommand('workbench.actions.view.problems');
                }
                else if (choice === btnWeb && result.reportUrl) {
                    vscode.env.openExternal(vscode.Uri.parse(result.reportUrl));
                }
            }
            else {
                vscode.window.showInformationMessage(`uncflow: Проверка завершена! Найдено ${total} замечаний. Критических уязвимостей нет.`);
            }
        }
        catch (err) {
            updateStatusBar('error');
            vscode.window.showErrorMessage(`Ошибка проверки uncflow: ${err.message}`);
        }
    });
}
function updateStatusBar(state, summary) {
    const scenarioTitle = workspaceState.lastScenarioTitle || 'Аудит';
    if (state === 'idle') {
        statusBarItem.text = `$(shield) uncflow: ${scenarioTitle} | ▶ Запуск`;
        statusBarItem.tooltip = 'Кликните для запуска аудита безопасности uncflow';
        statusBarItem.backgroundColor = undefined;
    }
    else if (state === 'running') {
        statusBarItem.text = `$(sync~spin) uncflow: сканирование...`;
        statusBarItem.tooltip = 'Выполняется сценарий анализа безопасности в uncflow';
        statusBarItem.backgroundColor = undefined;
    }
    else if (state === 'completed') {
        if (summary && (summary.critical > 0 || summary.high > 0)) {
            statusBarItem.text = `$(shield) ${summary.critical} Crit | ${summary.high} High | ▶ Повторить`;
            statusBarItem.tooltip = `Всего находок: ${summary.total} (Critical: ${summary.critical}, High: ${summary.high}, Medium: ${summary.medium}, Low: ${summary.low}). Кликните для повторного запуска.`;
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        }
        else {
            statusBarItem.text = `$(pass-filled) uncflow: Защищено (${summary?.total || 0}) | ▶`;
            statusBarItem.tooltip = 'Критических уязвимостей не обнаружено. Кликните для повторного запуска.';
            statusBarItem.backgroundColor = undefined;
        }
    }
    else if (state === 'error') {
        statusBarItem.text = `$(warning) uncflow: Ошибка | ▶ Повторить`;
        statusBarItem.tooltip = 'Произошла ошибка при обращении к uncflow. Кликните для повторной попытки.';
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
}
function deactivate() {
    diagnosticsManager.dispose();
}
//# sourceMappingURL=extension.js.map