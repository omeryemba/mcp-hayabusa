#!/bin/bash
# Stop hook: shows a Windows notification when the Claude Code session ends.
#
# Equivalent to the inline Stop hook command it replaces -- pops a native
# MessageBox via PowerShell announcing the session finished.

powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Claude Code session finished','Claude Code')"
