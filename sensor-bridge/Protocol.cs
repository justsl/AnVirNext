using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

internal sealed class SensorReading
{
    public string Id;
    public string Name;
    public string Hardware;
    public string Type;
    public double? Value;
}

internal static class SensorProtocol
{
    internal static string Serialize(IEnumerable<SensorReading> readings, IList<string> errors, bool driverAvailable, bool elevated)
    {
        var sensors = new List<Dictionary<string, object>>();
        int inspected = 0;
        foreach (SensorReading reading in readings)
        {
            if (++inspected > 4096 || sensors.Count == 1024) break;
            if (reading == null || string.IsNullOrEmpty(reading.Id) || !reading.Value.HasValue) continue;
            // LHM can return zero-filled MSR data when PawnIO cannot be opened.
            // CPU load uses OS counters; the other CPU sensors require the driver.
            if (!driverAvailable && reading.Type != "Load" &&
                (reading.Id.StartsWith("/amdcpu/", StringComparison.Ordinal) || reading.Id.StartsWith("/intelcpu/", StringComparison.Ordinal))) continue;
            double value = reading.Value.Value;
            if (double.IsNaN(value) || double.IsInfinity(value)) continue;
            sensors.Add(new Dictionary<string, object> {
                { "id", Clip(reading.Id, 256) }, { "name", Clip(reading.Name, 128) },
                { "hardware", Clip(reading.Hardware, 128) }, { "type", Clip(reading.Type, 32) }, { "value", value }
            });
        }

        var messages = new List<string>();
        for (int i = 0; i < errors.Count && messages.Count < 8; i++)
        {
            if (!string.IsNullOrEmpty(errors[i])) messages.Add(Clip(errors[i], 256));
        }

        var frame = new Dictionary<string, object> {
            { "version", 1 }, { "driver_available", driverAvailable }, { "elevated", elevated },
            { "sensors", sensors }, { "errors", messages }
        };
        var serializer = new JavaScriptSerializer { MaxJsonLength = 8 * 1048576 };
        while (true)
        {
            string json = serializer.Serialize(frame);
            if (Encoding.UTF8.GetByteCount(json) <= 1048576) return json;
            sensors.RemoveRange(sensors.Count / 2, sensors.Count - sensors.Count / 2);
        }
    }

    private static string Clip(string text, int length)
    {
        if (string.IsNullOrEmpty(text)) return "";
        if (text.Length <= length) return text;
        if (char.IsHighSurrogate(text[length - 1])) length--;
        return text.Substring(0, length);
    }
}
