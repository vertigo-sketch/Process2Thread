# Freeze Notepad UI thread (safe, reversible)
$p = Get-Process notepad
$sig = @"
using System;
using System.Runtime.InteropServices;
public class Block {
  [DllImport("kernel32.dll")]
  public static extern void Sleep(uint ms);
}
"@
Add-Type $sig
[Block]::Sleep(120000)