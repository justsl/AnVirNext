using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

internal static class ProtocolTests
{
    private static int _failures;

    private static int Main()
    {
        Run("preserves numeric zero and quoted sensor names", delegate {
            Dictionary<string, object> frame = Decode(new[] { Reading("/gpu/0/temperature/0", "GPU \"Core\"\nMain", 0) });
            Require(frame.ContainsKey("version") && Convert.ToInt32(frame["version"]) == 1, "missing protocol version");
            Require(frame.ContainsKey("sensors"), "missing sensor records");
            IList rows = (IList)frame["sensors"];
            Require(rows.Count == 1, "lost a valid zero reading");
            Dictionary<string, object> row = (Dictionary<string, object>)rows[0];
            Require(Convert.ToDouble(row["value"]) == 0, "zero must remain a number");
            Require((string)row["name"] == "GPU \"Core\"\nMain", "corrupted quoted/control characters");
        });
        Run("omits unavailable and nonfinite readings", delegate {
            Dictionary<string, object> frame = Decode(new[] {
                Reading("null", "Unavailable", null), Reading("nan", "Invalid", double.NaN),
                Reading("inf", "Invalid", double.PositiveInfinity), Reading("ok", "Valid", 23.5)
            });
            Require(frame.ContainsKey("sensors"), "missing sensor records");
            IList rows = (IList)frame["sensors"];
            Require(rows.Count == 1, "invalid readings were converted to values");
            Require((string)((Dictionary<string, object>)rows[0])["id"] == "ok", "discarded the valid reading");
        });
        Run("bounds record count", delegate {
            var rows = new List<SensorReading>();
            for (int i = 0; i < 1100; i++) rows.Add(Reading("/sensor/" + i, "Sensor", i));
            Dictionary<string, object> frame = Decode(rows);
            Require(frame.ContainsKey("sensors"), "missing sensor records");
            Require(((IList)frame["sensors"]).Count == 1024, "record bound not enforced");
        });
        Run("blocked CPU access does not publish fabricated zero temperatures", delegate {
            Dictionary<string, object> frame = Decode(new[] {
                Reading("/amdcpu/0/temperature/0", "CPU", 0),
                Reading("/nvidiagpu/0/temperature/0", "GPU", 0)
            });
            IList rows = (IList)frame["sensors"];
            Require(rows.Count == 1, "published a CPU temperature without driver access");
            Require((string)((Dictionary<string, object>)rows[0])["id"] == "/nvidiagpu/0/temperature/0", "discarded an accessible GPU reading");
        });
        Run("bounds error count and labels", delegate {
            var errors = new List<string>();
            for (int i = 0; i < 20; i++) errors.Add(new string('x', 1000));
            Dictionary<string, object> frame = Parse(SensorProtocol.Serialize(new SensorReading[0], errors, false, false));
            Require(frame.ContainsKey("errors"), "missing error list");
            IList values = (IList)frame["errors"];
            Require(values.Count == 8, "error count must be bounded");
            Require(((string)values[0]).Length == 256, "error text must be bounded");
        });
        Run("bounds UTF-8 frames even with control-character labels", delegate {
            var rows = new List<SensorReading>();
            for (int i = 0; i < 1024; i++) {
                SensorReading row = Reading(new string('\u0001', 256), new string('\u0001', 256), 1);
                row.Hardware = new string('\u0001', 256);
                rows.Add(row);
            }
            string json = SensorProtocol.Serialize(rows, new string[0], false, false);
            Require(Encoding.UTF8.GetByteCount(json) <= 1048576, "frame exceeded one MiB");
            Dictionary<string, object> frame = Parse(json);
            Require(frame.ContainsKey("sensors"), "missing sensor records");
            Require(((IList)frame["sensors"]).Count > 0, "all valid readings were lost");
        });
        Console.WriteLine(_failures == 0 ? "All 6 sensor protocol tests passed." : _failures + " sensor protocol tests failed.");
        return _failures == 0 ? 0 : 1;
    }

    private static SensorReading Reading(string id, string name, double? value)
    {
        return new SensorReading { Id = id, Name = name, Hardware = "GPU", Type = "Temperature", Value = value };
    }

    private static Dictionary<string, object> Decode(IEnumerable<SensorReading> rows)
    {
        return Parse(SensorProtocol.Serialize(rows, new string[0], false, false));
    }

    private static Dictionary<string, object> Parse(string json)
    {
        return new JavaScriptSerializer { MaxJsonLength = 1048576 }.Deserialize<Dictionary<string, object>>(json);
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void Run(string name, Action test)
    {
        try { test(); Console.WriteLine("PASS " + name); }
        catch (Exception error) { _failures++; Console.WriteLine("FAIL " + name + ": " + error.Message); }
    }
}
