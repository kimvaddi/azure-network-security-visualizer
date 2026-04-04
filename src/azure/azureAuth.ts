/**
 * Azure authentication via Entra ID (Azure AD).
 * Uses VS Code's built-in Azure Account session or falls back to interactive browser login.
 *
 * Microsoft Learn References:
 * - Azure Identity SDK: https://learn.microsoft.com/javascript/api/overview/azure/identity-readme
 * - Entra ID Authentication: https://learn.microsoft.com/entra/identity/
 * - VS Code Azure Account: https://learn.microsoft.com/azure/developer/javascript/how-to/with-visual-studio-code/install-azure-account
 */

import * as vscode from 'vscode';
import { TokenCredential } from '@azure/identity';
import { SubscriptionClient } from '@azure/arm-resources-subscriptions';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AzureSession {
  credential: TokenCredential;
  tenantId: string;
  subscriptions: SubscriptionInfo[];
}

export interface SubscriptionInfo {
  subscriptionId: string;
  displayName: string;
  tenantId: string;
}

// ─── Authentication ─────────────────────────────────────────────────────────

/**
 * Authenticate to Azure using VS Code's built-in Azure Account extension session.
 * Prompts the user to sign in if not already authenticated.
 */
export async function authenticateAzure(): Promise<AzureSession | null> {
  try {
    // Use VS Code's built-in Microsoft authentication provider (Entra ID)
    const session = await vscode.authentication.getSession('microsoft', [
      'https://management.azure.com/.default',
    ], { createIfNone: true });

    if (!session) {
      vscode.window.showWarningMessage('Azure sign-in was cancelled.');
      return null;
    }

    // Create a TokenCredential that uses the VS Code session token
    const credential = createVSCodeCredential(session);
    const tenantId = (session as { tenantId?: string }).tenantId ?? 'unknown';

    // List all accessible subscriptions
    const subscriptions = await listSubscriptions(credential);

    if (subscriptions.length === 0) {
      vscode.window.showWarningMessage('No Azure subscriptions found for this account.');
      return null;
    }

    return {
      credential,
      tenantId,
      subscriptions,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Azure authentication failed: ${msg}`);
    return null;
  }
}

/**
 * List all subscriptions accessible to the authenticated user.
 */
async function listSubscriptions(credential: TokenCredential): Promise<SubscriptionInfo[]> {
  const client = new SubscriptionClient(credential);
  const subscriptions: SubscriptionInfo[] = [];

  for await (const sub of client.subscriptions.list()) {
    if (sub.subscriptionId && sub.displayName) {
      subscriptions.push({
        subscriptionId: sub.subscriptionId,
        displayName: sub.displayName,
        tenantId: sub.tenantId ?? '',
      });
    }
  }

  return subscriptions;
}

/**
 * Show a multi-select picker for the user to choose which subscriptions to scan.
 */
export async function pickSubscriptions(subs: SubscriptionInfo[]): Promise<SubscriptionInfo[]> {
  const items = subs.map(s => ({
    label: s.displayName,
    description: s.subscriptionId,
    picked: true,  // All selected by default
    sub: s,
  }));

  const selected = await vscode.window.showQuickPick(items, {
    canPickMany: true,
    placeHolder: 'Select subscriptions to scan (all selected by default)',
    title: 'Azure Subscriptions',
  });

  if (!selected || selected.length === 0) {
    return [];
  }

  return selected.map(s => s.sub);
}

// ─── VS Code Token Credential Adapter ───────────────────────────────────────

/**
 * Wraps a VS Code AuthenticationSession as an Azure SDK TokenCredential.
 * This avoids needing InteractiveBrowserCredential (which opens external browser).
 */
function createVSCodeCredential(session: vscode.AuthenticationSession): TokenCredential {
  return {
    async getToken(_scopes: string | string[]) {
      // VS Code may have refreshed the token — get the latest session
      const freshSession = await vscode.authentication.getSession('microsoft', [
        'https://management.azure.com/.default',
      ], { silent: true });

      const token = freshSession?.accessToken ?? session.accessToken;

      return {
        token,
        expiresOnTimestamp: Date.now() + 3600 * 1000, // 1 hour estimate
      };
    },
  };
}
