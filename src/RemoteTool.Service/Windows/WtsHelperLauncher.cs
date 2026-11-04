using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using RemoteTool.Core.Audit;
using RemoteTool.Service.Helper;

namespace RemoteTool.Service.Windows;

/// <summary>
/// Starts the RemoteTool helper inside the console session with a SYSTEM token whose session id is changed to that session
/// (works at the login screen where no user token exists, and gives access to the secure desktop). Communication is over a
/// randomly named pipe whose ACL admits SYSTEM only; the connecting process id must be the one we just created.
/// Requires LocalSystem (SeTcbPrivilege, SeAssignPrimaryTokenPrivilege). NOT verifiable outside Windows: see docs/SERVICE.md.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WtsHelperLauncher : IHelperLauncher
{
    private readonly string _exe;
    private readonly IAuditLog _audit;

    public WtsHelperLauncher(string exePath, IAuditLog audit) { _exe = exePath; _audit = audit; }

    public int? ActiveSessionId()
    {
        var id = WTSGetActiveConsoleSessionId();
        return id == 0xFFFFFFFF ? null : (int)id;
    }

    public async Task<IHelperProcess> LaunchAsync(int sessionId, CancellationToken ct)
    {
        var pipeName = "RemoteTool.Helper." + Guid.NewGuid().ToString("N");
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        var server = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 64 * 1024, 64 * 1024, security);
        Process? proc = null;
        try
        {
            var pid = StartInSession(sessionId, $"\"{_exe}\" --helper --pipe {pipeName} --session {sessionId}");
            proc = Process.GetProcessById(pid);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            await server.WaitForConnectionAsync(timeout.Token).ConfigureAwait(false);
            if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var clientPid) || clientPid != (uint)pid)
                throw new InvalidOperationException("unexpected process connected to the helper pipe"); // someone else raced us
            _audit.Write("helper_launched", ("session", sessionId), ("pid", pid), ("user", UserOf(sessionId)));
            return new HelperProcess(server, proc);
        }
        catch
        {
            try { proc?.Kill(); } catch { }
            await server.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static int StartInSession(int sessionId, string commandLine)
    {
        IntPtr self = IntPtr.Zero, primary = IntPtr.Zero, env = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x000F01FF /* TOKEN_ALL_ACCESS */, out self)) throw new Win32Exception();
            if (!DuplicateTokenEx(self, 0x02000000 /* MAXIMUM_ALLOWED */, IntPtr.Zero, 2 /* SecurityImpersonation */, 1 /* TokenPrimary */, out primary)) throw new Win32Exception();
            var sid = sessionId;
            if (!SetTokenInformation(primary, 12 /* TokenSessionId */, ref sid, sizeof(int))) throw new Win32Exception();
            CreateEnvironmentBlock(out env, primary, false);
            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = "winsta0\\default" };
            const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            if (!CreateProcessAsUser(primary, null, commandLine, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT, env, Path.GetDirectoryName(Environment.ProcessPath), ref si, out var pi))
                throw new Win32Exception();
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return (int)pi.dwProcessId;
        }
        finally
        {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (primary != IntPtr.Zero) CloseHandle(primary);
            if (self != IntPtr.Zero) CloseHandle(self);
        }
    }

    private static string UserOf(int sessionId)
    {
        if (WTSQuerySessionInformation(IntPtr.Zero, sessionId, 5 /* WTSUserName */, out var buf, out _))
        {
            try { return Marshal.PtrToStringUni(buf) ?? ""; } finally { WTSFreeMemory(buf); }
        }
        return "";
    }

    private sealed class HelperProcess : IHelperProcess
    {
        private readonly Process _p;
        private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public HelperProcess(Stream pipe, Process p)
        {
            Pipe = pipe;
            _p = p;
            p.EnableRaisingEvents = true;
            p.Exited += (_, _) => _exited.TrySetResult();
            if (p.HasExited) _exited.TrySetResult();
        }
        public Stream Pipe { get; }
        public Task Exited => _exited.Task;
        public int ProcessId => _p.Id;
        public async ValueTask DisposeAsync()
        {
            try { if (!_p.HasExited) _p.Kill(); } catch { }
            await Pipe.DisposeAsync().ConfigureAwait(false);
            _p.Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb; public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attrs, int impersonation, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(IntPtr token, int infoClass, ref int info, int length);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(IntPtr token, string? app, string cmd, IntPtr procAttrs, IntPtr threadAttrs, bool inherit, uint flags, IntPtr env, string? cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool DestroyEnvironmentBlock(IntPtr env);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSQuerySessionInformation(IntPtr server, int session, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);
}
