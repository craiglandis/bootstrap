<#
User32.dll P/Invoke to call SystemParametersInfo SPI_SETSTICKYKEYS is from:

https://stackoverflow.com/questions/71854200/disable-shift-stickykey-shortcut/71860597#71860597

Setting the Flags reg value doesn't seem to work as reliably:

Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122"

#>

Add-Type -Namespace demo -Name StickyKeys -MemberDefinition '
  // The WinAPI P/Invoke declaration for SystemParametersInfo()
  [DllImport("user32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool SystemParametersInfo(uint uiAction, uint uiParam, ref STICKYKEYS pvParam, uint fWinIni);

  // The data structure used by SystemParametersInfo() to get and set StickyKey-related flags.
  [StructLayout(LayoutKind.Sequential)]
  struct STICKYKEYS {
    public uint  cbSize;
    public UInt32 dwFlags;
  }

  // A helper enum that represents a given combination of flags as a list of friendly symbolic identifiers.
  [Flags]
  public enum StickyKeyFlags : uint { // Prefix SKF_ omitted from the value names.
    AUDIBLEFEEDBACK = 0x00000040,
    AVAILABLE = 0x00000002,
    CONFIRMHOTKEY = 0x00000008,
    HOTKEYACTIVE = 0x00000004,
    HOTKEYSOUND = 0x00000010,
    INDICATOR = 0x00000020,
    STICKYKEYSON = 0x00000001,
    TRISTATE = 0x00000080,
    TWOKEYSOFF = 0x00000100,
    LALTLATCHED = 0x10000000,
    LCTLLATCHED = 0x04000000,
    LSHIFTLATCHED = 0x01000000,
    RALTLATCHED = 0x20000000,
    RCTLLATCHED = 0x08000000,
    RSHIFTLATCHED = 0x02000000,
    LALTLOCKED = 0x00100000,
    LCTLLOCKED = 0x00040000,
    LSHIFTLOCKED = 0x00010000,
    RALTLOCKED = 0x00200000,
    RCTLLOCKED = 0x00080000,
    RSHIFTLOCKED = 0x00020000,
    LWINLATCHED = 0x40000000,
    RWINLATCHED = 0x80000000,
    LWINLOCKED = 0x00400000,
    RWINLOCKED = 0x00800000
  }

  // Gets or set the enabled status of the sticky-keys hotkey.
  // Note: Setting is invariably *non-persistent*.
  //       Use the .EnableHotKey() method for optional persistence.
  public static bool IsHotKeyEnabled {
    get { return (GetFlags() & StickyKeyFlags.HOTKEYACTIVE) != 0u; }
    set { EnableHotKey(value, false); }
  }

  // Gets or set the active sticky-keys flags.
  // Note: Setting is invariably *non-persistent*.
  //       Use the .SetFlags() method for optional persistence.
  public static StickyKeyFlags ActiveFlags {
    get { return GetFlags(); }
    set { SetFlags(value, false); }
  }

  // The flags in effect on a pristine system.
  public static StickyKeyFlags DefaultFlags {
    get { return StickyKeyFlags.AVAILABLE | StickyKeyFlags.HOTKEYACTIVE | StickyKeyFlags.CONFIRMHOTKEY | StickyKeyFlags.HOTKEYSOUND | StickyKeyFlags.INDICATOR | StickyKeyFlags.AUDIBLEFEEDBACK | StickyKeyFlags.TRISTATE | StickyKeyFlags.TWOKEYSOFF; } // 510u
  }

  // Enable or disable the stick-keys hotkey, optionally persistently.
  public static void EnableHotKey(bool enable = true, bool persist = false) {
    var skInfo = new STICKYKEYS();
    skInfo.cbSize = (uint)Marshal.SizeOf(skInfo);
    var flags = GetFlags();
    SetFlags((enable ? flags | StickyKeyFlags.HOTKEYACTIVE : flags & ~StickyKeyFlags.HOTKEYACTIVE), persist);
  }

  // Get the currently active flags; exposed via the static .ActiveFlags property only.
  private static StickyKeyFlags GetFlags() {
    var skInfo = new STICKYKEYS();
    skInfo.cbSize = (uint)Marshal.SizeOf(skInfo);
    if (!SystemParametersInfo(0x003a /* SPI_GETSTICKYKEYS */, 0, ref skInfo, 0))
      throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    return (StickyKeyFlags)skInfo.dwFlags;
  }

  // Set the active flags *in full*, i.e. the value must combine all flags that should be set.
  // Best to start from the current combination of flags reported by .ActiveFlags.
  public static void SetFlags(StickyKeyFlags flags, bool persist = false) {
    var skInfo = new STICKYKEYS();
    skInfo.cbSize = (uint)Marshal.SizeOf(skInfo);
    skInfo.dwFlags = (UInt32)flags;
    if (!SystemParametersInfo(0x003b /* SPI_SETSTICKYKEYS */, 0, ref skInfo, persist ? 1u : 0u))
      throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  }
'

# Show the flags in effect by default, on a pristine system.
# [demo.StickyKeys]::DefaultFlags

# Get the active flags as a combination of friendly enum values; e.g.:
#   AVAILABLE, HOTKEYACTIVE, CONFIRMHOTKEY, HOTKEYSOUND, INDICATOR, AUDIBLEFEEDBACK, TRISTATE, TWOKEYSOFF
$activeFlags = [demo.StickyKeys]::ActiveFlags
Write-Output "Active flags: $activeFlags"

# Query if the hotkey is currently enabled.
$isStickyKeysHotKeyEnabled = [demo.StickyKeys]::IsHotKeyEnabled
Write-Output "Sticky Keys hotkey enabled: $isStickyKeysHotKeyEnabled"

# Disable the hotkey *for the current session*
# Afterwards, [demo.StickyKeys]::ActiveFlags output no longer contains HOTKEYACTIVE
Write-Output "Disabling Sticky Keys hotkey for current session"
[demo.StickyKeys]::IsHotKeyEnabled = $false

# Disable the hotkey *persistently*.
Write-Output "Disabling Sticky Keys hotkey persistently"
[demo.StickyKeys]::EnableHotKey($false, $true)

# Get the active flags as a combination of friendly enum values; e.g.:
#   AVAILABLE, HOTKEYACTIVE, CONFIRMHOTKEY, HOTKEYSOUND, INDICATOR, AUDIBLEFEEDBACK, TRISTATE, TWOKEYSOFF
$activeFlags = [demo.StickyKeys]::ActiveFlags
Write-Output "Active flags: $activeFlags"

# Query if the hotkey is currently enabled.
$isStickyKeysHotKeyEnabled = [demo.StickyKeys]::IsHotKeyEnabled
Write-Output "Sticky Keys hotkey enabled: $isStickyKeysHotKeyEnabled"