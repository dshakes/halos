# Windows service
`halod` is a plain console binary, not a native Windows service. Run it as SYSTEM
(needed to write `C:\Program Files\ClaudeCode\` and HKLM) using either:
- Scheduled task at startup (what the Intune script from `delivery/mdm` registers):
`schtasks /Create /TN Halos /RU SYSTEM /SC ONSTART /TR "\"C:\Program Files\Halos\halod.exe\" run --config \"C:\Program Files\Halos\etc\halod.yaml\" --state \"C:\Program Files\Halos\var\state.json\""`
- Or wrap with NSSM / WinSW to get restart-on-failure.
A native SCM service is not implemented.

Everything lives under `C:\Program Files\Halos\` (never `C:\ProgramData`, whose
default ACL lets any user create subdirectories and pre-seed a config). halod refuses
to start unless the config, public key, token file and state file are owned by
SYSTEM or Administrators (owner SID only; the DACL is not inspected, so harden it:
`icacls "C:\Program Files\Halos\etc" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F`).
Verified harness binaries install to `C:\Program Files\Halos\bin`; add it to
the machine PATH via MDM (halod creates no shims on Windows).
