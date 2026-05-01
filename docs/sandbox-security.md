# Sandbox Security

GuardChain dynamic analysis uses Docker as an isolation boundary. The default configuration applies:

- No network: `--network none`.
- Read-only root filesystem: `--read-only`.
- Non-root user: `--user 1000:1000`.
- Dropped capabilities: `--cap-drop ALL`.
- No new privileges: `--security-opt no-new-privileges`.
- Memory, CPU, and PID limits.
- `/tmp` mounted as `tmpfs` with `noexec,nosuid`.
- No host home directory mount.
- Only placeholder environment variables are passed into the container.

The target package is mounted read-only at `/package`. The output directory is limited to the trace/report mount used by GuardChain.

Dynamic analysis still executes untrusted code. Use it on a dedicated analysis machine or disposable VM when reviewing unknown packages.
