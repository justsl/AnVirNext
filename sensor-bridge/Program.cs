using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using LibreHardwareMonitor.Hardware;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

internal static class Program
{
    private static int Main(string[] arguments)
    {
        bool once = arguments.Length == 1 && arguments[0] == "--once";
        int parentId;
        Process parent = null;
        if (!once)
        {
            if (arguments.Length != 2 || arguments[0] != "--parent" || !int.TryParse(arguments[1], out parentId) || parentId <= 0)
                return 64;
            try { parent = Process.GetProcessById(parentId); }
            catch (ArgumentException) { return 0; }
        }

        Console.OutputEncoding = new UTF8Encoding(false);
        bool elevated;
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        bool driverAvailable = CanOpenPawnIo();

        var computer = new Computer { IsCpuEnabled = true, IsGpuEnabled = true, IsStorageEnabled = true };
        try
        {
            computer.Open();
            do
            {
                if (parent != null && parent.HasExited) break;
                var readings = new List<SensorReading>();
                var errors = new List<string>();
                foreach (IHardware hardware in computer.Hardware)
                    Collect(hardware, readings, errors, 0);
                Console.WriteLine(SensorProtocol.Serialize(readings, errors, driverAvailable, elevated));
                Console.Out.Flush();
                if (once) break;
                Thread.Sleep(2000);
            } while (true);
            return 0;
        }
        catch (IOException) { return 0; }
        catch (Exception error)
        {
            try { Console.WriteLine(SensorProtocol.Serialize(new SensorReading[0], new[] { "Hardware monitor: " + error.GetType().Name + ": " + error.Message }, driverAvailable, elevated)); }
            catch (IOException) { }
            return 1;
        }
        finally
        {
            computer.Close();
            if (parent != null) parent.Dispose();
        }
    }

    private static bool CanOpenPawnIo()
    {
        if (Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO", "DisplayVersion", null) == null) return false;
        using (SafeFileHandle handle = CreateFile(@"\\?\GLOBALROOT\Device\PawnIO", 0xC0000000, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero))
            return !handle.IsInvalid;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    private static void Collect(IHardware hardware, List<SensorReading> readings, List<string> errors, int depth)
    {
        if (depth > 8 || readings.Count >= 1024) return;
        try
        {
            hardware.Update();
            foreach (ISensor sensor in hardware.Sensors)
            {
                if (readings.Count == 1024) break;
                float? currentValue = sensor.Value;
                // The native UI owns bounded history; do not accumulate a second
                // per-sensor history inside the long-lived managed companion.
                sensor.ClearValues();
                if (!currentValue.HasValue) continue;
                readings.Add(new SensorReading {
                    Id = sensor.Identifier.ToString(), Name = sensor.Name, Hardware = hardware.Name,
                    Type = sensor.SensorType.ToString(), Value = currentValue.Value
                });
            }
        }
        catch (Exception error)
        {
            if (errors.Count < 8) errors.Add(hardware.Name + ": " + error.GetType().Name);
        }
        foreach (IHardware child in hardware.SubHardware)
            Collect(child, readings, errors, depth + 1);
    }
}
