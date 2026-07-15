import { execFile } from "node:child_process";

/**
 * Windows Hello via the WinRT UserConsentVerifier, driven from Windows
 * PowerShell (5.1 ships WinRT interop) — a real biometric/PIN prompt with no
 * native Node module. Electron has no built-in Hello API; safeStorage alone
 * is DPAPI, which decrypts silently for the logged-in user. This adds the
 * user-presence gate in front of it.
 */

const AWAIT_HELPER = `
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
  Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1' })[0]
function Await($op, $resultType) {
  $task = $asTaskGeneric.MakeGenericMethod($resultType).Invoke($null, @($op))
  $task.Wait(-1) | Out-Null
  $task.Result
}
[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
`;

function runPowershell(script: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
      { timeout: timeoutMs, windowsHide: true },
      (err, stdout) => (err ? reject(err) : resolve(stdout.trim()))
    );
  });
}

/** Is Windows Hello (biometric or PIN) set up on this machine? */
export async function helloAvailable(): Promise<boolean> {
  if (process.platform !== "win32") return false;
  try {
    const out = await runPowershell(
      AWAIT_HELPER +
        `Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])`,
      15_000
    );
    return out === "Available";
  } catch {
    return false;
  }
}

/** Show the Hello prompt. True only when the user verifies successfully. */
export async function helloPrompt(reason: string): Promise<boolean> {
  if (process.platform !== "win32") return false;
  const safeReason = reason.replace(/[^\w .,!?-]/g, "").slice(0, 120);
  try {
    const out = await runPowershell(
      AWAIT_HELPER +
        `Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("${safeReason}")) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])`,
      120_000 // the user may take a while at the prompt
    );
    return out === "Verified";
  } catch {
    return false;
  }
}
