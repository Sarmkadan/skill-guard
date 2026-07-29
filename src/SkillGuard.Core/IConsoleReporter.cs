using System.IO;

namespace SkillGuard.Core;

/// <summary>
/// Interface exposing the instance members of <see cref="ConsoleReporter"/>.
/// </summary>
public interface IConsoleReporter
{
    /// <summary>
    /// Writes the scan report to the provided <see cref="TextWriter"/> in a human‑readable format.
    /// </summary>
    /// <param name="report">The scan report containing findings to report.</param>
    /// <param name="output">The text writer to write the console output to.</param>
    void Write(ScanReport report, TextWriter output);
}
