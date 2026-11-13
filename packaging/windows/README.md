# Vigil on Windows

Vigil runs as a native Windows service (Service Control Manager). The
service runs as `NT AUTHORITY\LocalService` (least-privileged built-in
account with network access) and restarts automatically on failure.

## Install

From an elevated PowerShell, in the extracted release zip:

```powershell
.\install-service.ps1 -Config .\vigil.example.toml -EnvFile .\vigil.env
```

The script:

1. copies `vigil.exe` to `C:\Program Files\LLCForge\vigil\`;
2. creates `C:\ProgramData\LLCForge\vigil\` (queue, silences, state) and
   restricts it to SYSTEM, Administrators and LocalService;
3. copies the configuration to `C:\ProgramData\LLCForge\vigil\vigil.toml`
   (an existing file is kept);
4. runs `vigil service install --config <path>`;
5. stores `STATE_DIRECTORY` and the secrets from `-EnvFile` in the service's
   registry `Environment` value and starts the service.

Secrets in the registry are readable by local administrators. Configuration
files only ever contain the *names* of environment variables (`*_env`).

## Manage

```powershell
sc.exe query vigil
Restart-Service vigil          # also reloads configuration
& "C:\Program Files\LLCForge\vigil\vigil.exe" service uninstall
```

`vigil service run` started from a console (not by the SCM) runs in the
foreground, which is handy for debugging; Ctrl-C stops it. The configuration
file is also polled every few seconds, so most edits apply without a restart.

## Firewall

Only open the metrics/health port (9184) to your monitoring hosts:

```powershell
New-NetFirewallRule -DisplayName "Vigil metrics" -Direction Inbound -Protocol TCP -LocalPort 9184 -RemoteAddress 192.0.2.0/24 -Action Allow
```
