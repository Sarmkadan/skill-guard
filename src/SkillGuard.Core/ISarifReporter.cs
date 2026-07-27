namespace SkillGuard.Core
{
    /// <summary>
    /// Interface for SARIF reporters.
    /// </summary>
    public interface ISarifReporter
    {
        /// <summary>
        /// Writes the scan report in SARIF format to the specified output.
        /// </summary>
        /// <param name="report">The scan report containing findings to report.</param>
        /// <param name="output">The text writer to write the SARIF output to.</param>
        void Write(ScanReport report, TextWriter output);
    }
}
