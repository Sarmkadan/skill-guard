# SourceLocation

`SourceLocation` and its associated record types (`Finding`, `ScanTarget`, `ScanReport`) constitute the core data model for the `skill-guard` scanning engine, defining the representation of files, security findings, and the aggregated results of a scan. These types are designed to support immutable analysis, allowing scanners to track, categorize, and report security vulnerabilities within a codebase effectively.

## API

### SourceLocation
Represents a specific position within a source file.

*   `public static SourceLocation At(string filePath, int line)`: Creates a new `SourceLocation` instance for the specified file path and line number.
*   `public override string ToString()`: Returns a string representation of the source location, typically in the format `filePath:line`.

### Finding
Represents a security-relevant discovery made during scanning.

*   `public string? Remediation`: Contains optional guidance on how to resolve the identified security finding. Returns `null` if no specific remediation is available.

### ScanTarget
Represents an input file processed by the scanner.

*   `public string[] Lines`: An array containing the raw content of the scanned file, split by line.
*   `public static ScanTarget FromFile(string path)`: Loads the content from a file located at the specified path and returns a `ScanTarget` instance. Throws an `IOException` if the file cannot be accessed.

### ScanReport
Represents the comprehensive output of a security scan.

*   `public int CountAtOrAbove(int severityThreshold)`: Returns the total number of findings identified in the scan that have a severity level greater than or equal to the provided `severityThreshold`.
*   `public IEnumerable<IGrouping<string, Finding>> ByFile`: A collection of findings grouped by the file path where they were detected, allowing for efficient iteration and reporting per file.

## Usage

### Example 1: Creating a Scan Target and Inspecting Findings
```csharp
// Load a file into a scan target
var target = ScanTarget.FromFile("instructions.md");

// Retrieve findings (assuming a hypothetical scanner engine)
var report = scanner.Scan(target);

// Access findings grouped by file
foreach (var fileGroup in report.ByFile)
{
    Console.WriteLine($"Findings in {fileGroup.Key}:");
    foreach (var finding in fileGroup)
    {
        Console.WriteLine($" - Issue found. Remediation: {finding.Remediation ?? "None provided."}");
    }
}
```

### Example 2: Filtering Findings by Severity
```csharp
// Assuming a ScanReport named 'report'
int threshold = 5;

// Count high-severity findings
int highSeverityCount = report.CountAtOrAbove(threshold);

Console.WriteLine($"Found {highSeverityCount} issues with severity >= {threshold}.");
```

## Notes

*   **Immutability:** All types are implemented as `sealed record` types, ensuring that instances are immutable after creation. This design simplifies state management during parallel scanning operations.
*   **Thread Safety:** Because these types are immutable, they are inherently thread-safe. Multiple threads can safely read from `ScanReport` or `ScanTarget` instances concurrently without locking.
*   **Edge Cases:**
    *   `ScanTarget.FromFile`: This method assumes the existence and readability of the target file. If the file is locked, missing, or lacks sufficient permissions, an exception will be raised by the underlying file system operations.
    *   `Remediation`: Consumers must handle potential `null` values for `Remediation` properties, as not all security findings will necessarily have actionable fix instructions.
