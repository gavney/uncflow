import * as vscode from 'vscode';
import { UncflowClient } from './api/client';
import { DiagnosticsManager } from './providers/diagnostics';
import { FindingsTreeProvider } from './providers/findingsTree';
import { DetailsViewProvider } from './providers/detailsView';
import { UncflowQuickFixProvider } from './providers/quickFix';
import { WorkspaceState } from './state/workspace';
import { createProjectZipBuffer } from './utils/archiver';
import { AuditSummary } from './types';
import { execFile } from 'child_process';
import { promisify } from 'util';

let statusBarItem: vscode.StatusBarItem;
const diagnosticsManager = new DiagnosticsManager();
const workspaceState = WorkspaceState.getInstance();
let client: UncflowClient;
const execFileAsync = promisify(execFile);

async function getGitRemote(folderPath: string): Promise<{ url: string; branch: string } | undefined> {
  try {
    const { stdout: urlOut } = await execFileAsync('git', ['config', '--get', 'remote.origin.url'], { cwd: folderPath });
    const url = urlOut.trim();
    if (!url) return undefined;
    const { stdout: branchOut } = await execFileAsync('git', ['branch', '--show-current'], { cwd: folderPath });
    return { url, branch: branchOut.trim() || 'main' };
  } catch {
    return undefined;
  }
}

async function loginToServer(): Promise<boolean> {
  const email = await vscode.window.showInputBox({
    prompt: 'Email для входа в uncflow',
    ignoreFocusOut: true
  });
  if (!email) return false;

  const password = await vscode.window.showInputBox({
    prompt: 'Пароль',
    password: true,
    ignoreFocusOut: true
  });
  if (!password) return false;

  try {
    const serverUrl = vscode.workspace.getConfiguration('uncflow')
      .get<string>('serverUrl', 'https://uncflow.duckdns.org')
      .trim()
      .replace(/\/+$/, '');
    const response = await fetch(`${serverUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim(), password })
    });
    const responseText = await response.text();
    let data: { token?: string; user?: { name?: string }; error?: string };
    try {
      data = JSON.parse(responseText);
    } catch {
      const detail = responseText.trim()
        ? ` Ответ сервера: ${responseText.trim().slice(0, 200)}`
        : ' Сервер вернул пустой ответ.';
      throw new Error(`Некорректный ответ сервера (HTTP ${response.status}).${detail}`);
    }

    if (!response.ok || !data.token) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }

    await client.setAuthToken(data.token);
    void vscode.window.showInformationMessage(`uncflow: выполнен вход как ${data.user?.name || email}`);
    return true;
  } catch (err: any) {
    void vscode.window.showErrorMessage(`Ошибка входа uncflow: ${err.message}`);
    return false;
  }
}

export function activate(context: vscode.ExtensionContext) {
  workspaceState.init(context);
  client = new UncflowClient(context);
  void client.loadAuthToken();

  // 1. Status Bar widget
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'uncflow.runLastScenario';
  updateStatusBar('idle');
  statusBarItem.show();

  // 2. Register TreeDataProvider & Webview View
  const treeProvider = new FindingsTreeProvider();
  vscode.window.registerTreeDataProvider('uncflow.views.findings', treeProvider);

  const detailsProvider = new DetailsViewProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('uncflow.views.details', detailsProvider)
  );

  // 3. Register CodeActionProvider (QuickFix)
  const quickFixProvider = new UncflowQuickFixProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      quickFixProvider,
      { providedCodeActionKinds: UncflowQuickFixProvider.providedCodeActionKinds }
    )
  );

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
    } catch (err: any) {
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
    const url = config.get<string>('serverUrl', 'https://uncflow.duckdns.org');
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
    const runOnSave = config.get<boolean>('runOnSave', false);
    if (!runOnSave) return;

    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
      await executeAudit(folders[0].uri.fsPath, workspaceState.lastScenarioId, workspaceState.lastScenarioTitle);
    }
  });

  context.subscriptions.push(
    statusBarItem,
    diagnosticsManager,
    runLastCmd,
    selectCmd,
    scanFileCmd,
    openDashboardCmd,
    openSettingsCmd,
    loginCmd,
    logoutCmd,
    clearCmd,
    refreshTreeCmd,
    showDetailsCmd,
    onSaveListener
  );
}

async function executeAudit(folderPath: string, scenarioId: string, scenarioTitle: string) {
  await client.loadAuthToken();
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'uncflow Security Platform',
      cancellable: false
    },
    async (progress) => {
      updateStatusBar('running');
      progress.report({ message: 'Подготовка к аудиту проекта...' });

      try {
        let codePath = folderPath;

        const isLocal = client.isLocalHost();

        if (!isLocal) {
          progress.report({ message: 'Упаковка проекта в безопасный ZIP-архив...' });
          try {
            const zipBuffer = await createProjectZipBuffer(folderPath);
            progress.report({ message: 'Передача ZIP-архива на сервер uncflow...' });
            const uploadRes = await client.uploadArchive(zipBuffer, 'vscode-project.zip');
            codePath = uploadRes.path;
            progress.report({ message: `Загружено файлов: ${uploadRes.fileCount}. Запуск проверки...` });
          } catch (uploadError: any) {
            if (!/Not found|404/i.test(uploadError.message)) throw uploadError;

            const remote = await getGitRemote(folderPath);
            if (!remote) {
              throw new Error(
                'Сервер не поддерживает /api/sources/local-archive. Откройте проект как Git-репозиторий с настроенным origin или обновите backend на сервере.'
              );
            }

            progress.report({ message: 'Сервер не принимает ZIP: запуск проверки Git origin...' });
            vscode.window.showWarningMessage(
              'На удалённом сервере недоступна загрузка ZIP. Будет проанализирована версия из Git origin, без несохранённых локальных изменений.'
            );
            codePath = '';
            (global as any).__uncflowRepository = remote;
          }
        }

        progress.report({ message: `Выполнение сценария "${scenarioTitle}"...` });
        const repository = (global as any).__uncflowRepository as { url: string; branch: string } | undefined;
        delete (global as any).__uncflowRepository;
        const runParams = {
          codePath: codePath || undefined,
          repository: repository?.url,
          branch: repository?.branch
        };
        let result;
        try {
          result = await client.runAudit(scenarioId, runParams);
        } catch (err: any) {
          if (!/Неверный или отсутствующий токен авторизации CI|401|unauthorized/i.test(err.message)) {
            throw err;
          }

          const loginAction = 'Войти в uncflow';
          const action = await vscode.window.showErrorMessage(
            'Для аудита на сервере требуется авторизация. Войдите в uncflow, чтобы продолжить.',
            loginAction
          );
          if (action !== loginAction || !(await loginToServer())) return;
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
          const choice = await vscode.window.showErrorMessage(
            `uncflow: Обнаружено ${total} проблем безопасности (${critical} Critical, ${high} High)!`,
            btnView,
            btnWeb
          );
          if (choice === btnView) {
            vscode.commands.executeCommand('workbench.actions.view.problems');
          } else if (choice === btnWeb && result.reportUrl) {
            vscode.env.openExternal(vscode.Uri.parse(result.reportUrl));
          }
        } else {
          vscode.window.showInformationMessage(
            `uncflow: Проверка завершена! Найдено ${total} замечаний. Критических уязвимостей нет.`
          );
        }
      } catch (err: any) {
        updateStatusBar('error');
        vscode.window.showErrorMessage(`Ошибка проверки uncflow: ${err.message}`);
      }
    }
  );
}

function updateStatusBar(
  state: 'idle' | 'running' | 'completed' | 'error',
  summary?: AuditSummary
) {
  const scenarioTitle = workspaceState.lastScenarioTitle || 'Аудит';

  if (state === 'idle') {
    statusBarItem.text = `$(shield) uncflow: ${scenarioTitle} | ▶ Запуск`;
    statusBarItem.tooltip = 'Кликните для запуска аудита безопасности uncflow';
    statusBarItem.backgroundColor = undefined;
  } else if (state === 'running') {
    statusBarItem.text = `$(sync~spin) uncflow: сканирование...`;
    statusBarItem.tooltip = 'Выполняется сценарий анализа безопасности в uncflow';
    statusBarItem.backgroundColor = undefined;
  } else if (state === 'completed') {
    if (summary && (summary.critical > 0 || summary.high > 0)) {
      statusBarItem.text = `$(shield) ${summary.critical} Crit | ${summary.high} High | ▶ Повторить`;
      statusBarItem.tooltip = `Всего находок: ${summary.total} (Critical: ${summary.critical}, High: ${summary.high}, Medium: ${summary.medium}, Low: ${summary.low}). Кликните для повторного запуска.`;
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else {
      statusBarItem.text = `$(pass-filled) uncflow: Защищено (${summary?.total || 0}) | ▶`;
      statusBarItem.tooltip = 'Критических уязвимостей не обнаружено. Кликните для повторного запуска.';
      statusBarItem.backgroundColor = undefined;
    }
  } else if (state === 'error') {
    statusBarItem.text = `$(warning) uncflow: Ошибка | ▶ Повторить`;
    statusBarItem.tooltip = 'Произошла ошибка при обращении к uncflow. Кликните для повторной попытки.';
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }
}

export function deactivate() {
  diagnosticsManager.dispose();
}
