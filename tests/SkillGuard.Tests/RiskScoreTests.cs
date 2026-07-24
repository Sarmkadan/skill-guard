using SkillGuard.Core;
using Xunit;

namespace SkillGuard.Tests;

/// <summary>
/// Comprehensive unit tests for RiskScore grade-boundary computation.
/// Tests all severity/count combinations and edge cases.
/// </summary>
public class RiskScoreTests
{
    private static Finding Make(Severity severity) =>
        new("SGX", "X", severity, FindingCategory.PromptInjection, "m",
            SourceLocation.At("/f", 1, 1, 1), "s");

    private static ScanReport Report(params Severity[] severities) =>
        new(severities.Select(Make).ToList(), 1, 1, TimeSpan.Zero);

    private static ScanReport ReportWithCounts(IReadOnlyDictionary<Severity, int> counts)
    {
        var findings = new List<Finding>();
        foreach (var kvp in counts)
        {
            for (int i = 0; i < kvp.Value; i++)
            {
                findings.Add(Make(kvp.Key));
            }
        }
        return new ScanReport(findings, 1, 1, TimeSpan.Zero);
    }

    /// <summary>
    /// Test: Zero findings should result in Points=0 and Grade='A'
    /// </summary>
    [Fact]
    public void ZeroFindings_ResultsInPointsZeroAndGradeA()
    {
        var score = RiskScore.From(Report());
        Assert.Equal(0, score.Points);
        Assert.Equal('A', score.Grade);
        Assert.Empty(score.Counts);
    }

    /// <summary>
    /// Test: Empty counts dictionary should result in Points=0 and Grade='A'
    /// </summary>
    [Fact]
    public void EmptyCountsDictionary_ResultsInPointsZeroAndGradeA()
    {
        var emptyCounts = new Dictionary<Severity, int>();
        var score = new RiskScore(0, 'A', emptyCounts);
        Assert.Equal(0, score.Points);
        Assert.Equal('A', score.Grade);
        Assert.Empty(score.Counts);
    }

    /// <summary>
    /// Test: Grade A boundary - exactly 0 points
    /// </summary>
    [Fact]
    public void GradeA_BoundaryAtZeroPoints()
    {
        var score = new RiskScore(0, 'A', new Dictionary<Severity, int>());
        Assert.Equal(0, score.Points);
        Assert.Equal('A', score.Grade);
    }

    /// <summary>
    /// Test: Grade A boundary - boundary-1 (should still be A)
    /// </summary>
    [Fact]
    public void GradeA_BoundaryMinusOne_IsStillA()
    {
        var score = new RiskScore(-1, 'A', new Dictionary<Severity, int>());
        Assert.Equal(-1, score.Points);
        Assert.Equal('A', score.Grade);
    }

    /// <summary>
    /// Test: Grade B boundary - exactly 1 point (lowest point that gives B)
    /// </summary>
    [Fact]
    public void GradeB_BoundaryAtOnePoint()
    {
        var score = new RiskScore(1, 'B', new Dictionary<Severity, int> { { Severity.Low, 1 } });
        Assert.Equal(1, score.Points);
        Assert.Equal('B', score.Grade);
    }

    /// <summary>
    /// Test: Grade B boundary - boundary+1 (should still be B)
    /// </summary>
    [Fact]
    public void GradeB_BoundaryPlusOne_IsStillB()
    {
        var score = new RiskScore(5, 'B', new Dictionary<Severity, int> { { Severity.Medium, 1 } });
        Assert.Equal(5, score.Points);
        Assert.Equal('B', score.Grade);
    }

    /// <summary>
    /// Test: Grade B boundary - boundary (should be B)
    /// </summary>
    [Fact]
    public void GradeB_BoundaryAtFourPoints()
    {
        var score = new RiskScore(4, 'B', new Dictionary<Severity, int> { { Severity.Low, 4 } });
        Assert.Equal(4, score.Points);
        Assert.Equal('B', score.Grade);
    }

    /// <summary>
    /// Test: Grade B boundary - boundary+1 (should still be B)
    /// </summary>
    [Fact]
    public void GradeB_BoundaryAtFivePoints()
    {
        var score = new RiskScore(5, 'B', new Dictionary<Severity, int> { { Severity.Medium, 1 } });
        Assert.Equal(5, score.Points);
        Assert.Equal('B', score.Grade);
    }

    /// <summary>
    /// Test: Grade C boundary - exactly 15 points (highest point that gives C)
    /// </summary>
    [Fact]
    public void GradeC_BoundaryAtFifteenPoints()
    {
        // 3 High = 45 points (too high)
        // 2 High = 30 points (too high)
        // 1 High + 3 Medium = 15 + 15 = 30 (too high)
        // Need exactly 15 points: 3 Medium = 15
        var score = new RiskScore(15, 'C', new Dictionary<Severity, int> { { Severity.Medium, 3 } });
        Assert.Equal(15, score.Points);
        Assert.Equal('C', score.Grade);
    }

    /// <summary>
    /// Test: Grade C boundary - boundary+1 (should still be C)
    /// </summary>
    [Fact]
    public void GradeC_BoundaryAtFourteenPoints()
    {
        var score = new RiskScore(14, 'C', new Dictionary<Severity, int> { { Severity.Medium, 14 / 5 } });
        Assert.Equal(14, score.Points);
        Assert.Equal('C', score.Grade);
    }

    /// <summary>
    /// Test: Grade D boundary - exactly 40 points (highest point that gives D)
    /// </summary>
    [Fact]
    public void GradeD_BoundaryAtFortyPoints()
    {
        // 1 Critical = 40 points
        var counts = new Dictionary<Severity, int> { { Severity.Critical, 1 } };
        var score = new RiskScore(40, 'D', counts);
        Assert.Equal(40, score.Points);
        Assert.Equal('D', score.Grade);
    }

    /// <summary>
    /// Test: Grade D boundary - boundary+1 (should still be D)
    /// </summary>
    [Fact]
    public void GradeD_BoundaryAtThirtyNinePoints()
    {
        // 2 High + 1 Medium + 4 Low = 30 + 5 + 4 = 39
        var counts = new Dictionary<Severity, int> { { Severity.High, 2 }, { Severity.Medium, 1 }, { Severity.Low, 4 } };
        var score = new RiskScore(39, 'D', counts);
        Assert.Equal(39, score.Points);
        Assert.Equal('D', score.Grade);
    }

    /// <summary>
    /// Test: Grade F boundary - exactly 41 points (lowest point that gives F)
    /// </summary>
    [Fact]
    public void GradeF_BoundaryAtFortyOnePoints()
    {
        // 1 Critical + 1 Low = 40 + 1 = 41
        var counts = new Dictionary<Severity, int> { { Severity.Critical, 1 }, { Severity.Low, 1 } };
        var score = new RiskScore(41, 'F', counts);
        Assert.Equal(41, score.Points);
        Assert.Equal('F', score.Grade);
    }

    /// <summary>
    /// Test: Single Critical finding forces worst-case grade (F) regardless of low total points
    /// Verifies the 'any critical finding caps the grade' rule
    /// </summary>
    [Fact]
    public void SingleCriticalFinding_ForcesGradeF()
    {
        var score = RiskScore.From(Report(Severity.Critical));
        Assert.Equal(40, score.Points);
        Assert.Equal('F', score.Grade);
    }

    /// <summary>
    /// Test: Multiple Critical findings maintain worst-case grade
    /// </summary>
    [Fact]
    public void MultipleCriticalFindings_ForceGradeF()
    {
        var score = RiskScore.From(Report(Severity.Critical, Severity.Critical, Severity.Critical));
        Assert.Equal(120, score.Points);
        Assert.Equal('F', score.Grade);
    }

    /// <summary>
    /// Test: Critical finding with other severities still results in F grade
    /// </summary>
    [Fact]
    public void CriticalWithOtherSeverities_ResultsInGradeF()
    {
        var score = RiskScore.From(Report(Severity.Critical, Severity.High, Severity.Medium, Severity.Low));
        Assert.Equal(61, score.Points); // 40 + 15 + 5 + 1
        Assert.Equal('F', score.Grade);
    }

    /// <summary>
    /// Test: Counts dictionary with severity key present but count=0 produces same Points as key absent
    /// </summary>
    [Fact]
    public void CountsWithZeroValue_EqualsAbsentKey()
    {
        var reportWithKey = ReportWithCounts(new Dictionary<Severity, int> { { Severity.Critical, 0 } });
        var reportWithoutKey = ReportWithCounts(new Dictionary<Severity, int>());

        var scoreWithKey = RiskScore.From(reportWithKey);
        var scoreWithoutKey = RiskScore.From(reportWithoutKey);

        Assert.Equal(0, scoreWithKey.Points);
        Assert.Equal(0, scoreWithoutKey.Points);
        Assert.Equal(scoreWithKey.Points, scoreWithoutKey.Points);
        Assert.Equal('A', scoreWithKey.Grade);
        Assert.Equal('A', scoreWithoutKey.Grade);
    }

    /// <summary>
    /// Test: Counts dictionary with multiple severities including zero values
    /// </summary>
    [Fact]
    public void CountsWithMultipleSeveritiesIncludingZero_ComputesCorrectly()
    {
        var counts = new Dictionary<Severity, int> {
            { Severity.Critical, 0 },
            { Severity.High, 2 },
            { Severity.Medium, 0 },
            { Severity.Low, 5 }
        };
        var report = ReportWithCounts(counts);
        var score = RiskScore.From(report);

        // Should only count High=2 and Low=5: 15*2 + 1*5 = 35
        Assert.Equal(35, score.Points);
        Assert.Equal('D', score.Grade);
    }

    /// <summary>
    /// Test: Very large counts of Low-severity findings (10,000) doesn't overflow int
    /// </summary>
    [Fact]
    public void LargeCountsOfLowSeverity_DoesNotOverflow()
    {
        var counts = new Dictionary<Severity, int> { { Severity.Low, 10000 } };
        var report = ReportWithCounts(counts);
        var score = RiskScore.From(report);

        Assert.Equal(10000, score.Points);
        Assert.Equal('F', score.Grade);
        Assert.Equal(10000, score.Counts[Severity.Low]);
    }

    /// <summary>
    /// Test: Very large counts of Medium-severity findings (10,000) doesn't overflow int
    /// </summary>
    [Fact]
    public void LargeCountsOfMediumSeverity_DoesNotOverflow()
    {
        var counts = new Dictionary<Severity, int> { { Severity.Medium, 10000 } };
        var report = ReportWithCounts(counts);
        var score = RiskScore.From(report);

        Assert.Equal(50000, score.Points);
        Assert.Equal('F', score.Grade);
        Assert.Equal(10000, score.Counts[Severity.Medium]);
    }

    /// <summary>
    /// Test: Very large counts of High-severity findings (10,000) doesn't overflow int
    /// </summary>
    [Fact]
    public void LargeCountsOfHighSeverity_DoesNotOverflow()
    {
        var counts = new Dictionary<Severity, int> { { Severity.High, 10000 } };
        var report = ReportWithCounts(counts);
        var score = RiskScore.From(report);

        Assert.Equal(150000, score.Points);
        Assert.Equal('F', score.Grade);
        Assert.Equal(10000, score.Counts[Severity.High]);
    }

    /// <summary>
    /// Test: Very large counts of Critical-severity findings (10,000) doesn't overflow int
    /// </summary>
    [Fact]
    public void LargeCountsOfCriticalSeverity_DoesNotOverflow()
    {
        var counts = new Dictionary<Severity, int> { { Severity.Critical, 10000 } };
        var report = ReportWithCounts(counts);
        var score = RiskScore.From(report);

        Assert.Equal(400000, score.Points);
        Assert.Equal('F', score.Grade);
        Assert.Equal(10000, score.Counts[Severity.Critical]);
    }

    /// <summary>
    /// Test: Mixed severities with large counts computes correctly
    /// </summary>
    [Fact]
    public void MixedSeveritiesWithLargeCounts_ComputesCorrectly()
    {
        var counts = new Dictionary<Severity, int> {
            { Severity.Critical, 100 },
            { Severity.High, 200 },
            { Severity.Medium, 300 },
            { Severity.Low, 400 }
        };
        var report = ReportWithCounts(counts);
        var score = RiskScore.From(report);

        var expectedPoints = 40*100 + 15*200 + 5*300 + 1*400;
        Assert.Equal(expectedPoints, score.Points);
        Assert.Equal('F', score.Grade);
        Assert.Equal(100, score.Counts[Severity.Critical]);
        Assert.Equal(200, score.Counts[Severity.High]);
        Assert.Equal(300, score.Counts[Severity.Medium]);
        Assert.Equal(400, score.Counts[Severity.Low]);
    }

    /// <summary>
    /// Test: Grade computation from actual RiskScore.From() with various combinations
    /// </summary>
    [Theory]
    [InlineData(new object[] { new Severity[] { }, 0, 'A' })] // No findings
    [InlineData(new object[] { new Severity[] { Severity.Low }, 1, 'B' })] // 1 Low
    [InlineData(new object[] { new Severity[] { Severity.Low, Severity.Low }, 2, 'B' })] // 2 Low
    [InlineData(new object[] { new Severity[] { Severity.Low, Severity.Low, Severity.Low }, 3, 'B' })] // 3 Low
    [InlineData(new object[] { new Severity[] { Severity.Low, Severity.Low, Severity.Low, Severity.Low }, 4, 'B' })] // 4 Low
    [InlineData(new object[] { new Severity[] { Severity.Medium }, 5, 'C' })] // 1 Medium = 5 points → 'C'
    [InlineData(new object[] { new Severity[] { Severity.Medium, Severity.Medium }, 10, 'C' })] // 2 Medium = 10 points → 'C'
    [InlineData(new object[] { new Severity[] { Severity.Medium, Severity.Medium, Severity.Medium }, 15, 'D' })] // 3 Medium = 15 points → 'D'
    [InlineData(new object[] { new Severity[] { Severity.High }, 15, 'D' })] // 1 High = 15 points → 'D'
    [InlineData(new object[] { new Severity[] { Severity.High, Severity.High }, 30, 'D' })] // 2 High = 30 points → 'D'
    [InlineData(new object[] { new Severity[] { Severity.High, Severity.High, Severity.High }, 45, 'F' })] // 3 High = 45 points → 'F'
    [InlineData(new object[] { new Severity[] { Severity.Critical }, 40, 'F' })] // 1 Critical = 40 points → 'F'
    [InlineData(new object[] { new Severity[] { Severity.Critical, Severity.Low }, 41, 'F' })] // 1 Critical + 1 Low = 41 points → 'F'
    public void GradeBoundaries_FromVariousCombinations(Severity[] severities, int expectedPoints, char expectedGrade)
    {
        var report = Report(severities);
        var score = RiskScore.From(report);
        Assert.Equal(expectedPoints, score.Points);
        Assert.Equal(expectedGrade, score.Grade);
    }

    /// <summary>
    /// Test: RiskScore.Weight returns correct values for all severities
    /// </summary>
    [Theory]
    [InlineData(Severity.Critical, 40)]
    [InlineData(Severity.High, 15)]
    [InlineData(Severity.Medium, 5)]
    [InlineData(Severity.Low, 1)]
    [InlineData(Severity.Note, 0)]
    public void Weight_ReturnsCorrectValues(Severity severity, int expectedWeight)
    {
        var weight = RiskScore.Weight(severity);
        Assert.Equal(expectedWeight, weight);
    }

    /// <summary>
    /// Test: GradeFor private method returns correct grades for all boundaries
    /// </summary>
    [Theory]
    [InlineData(0, 'A')]
    [InlineData(1, 'B')]
    [InlineData(2, 'B')]
    [InlineData(3, 'B')]
    [InlineData(4, 'B')]
    [InlineData(5, 'C')] // 5 → C (5-14 inclusive)
    [InlineData(10, 'C')]
    [InlineData(14, 'C')]
    [InlineData(15, 'D')] // 15 → D (15-39 inclusive)
    [InlineData(20, 'D')]
    [InlineData(39, 'D')]
    [InlineData(40, 'F')] // 40 → F (40+)
    [InlineData(41, 'F')]
    [InlineData(100, 'F')]
    [InlineData(1000, 'F')]
    public void GradeFor_ReturnsCorrectGrades(int points, char expectedGrade)
    {
        // Use reflection to test the private method
        var method = typeof(RiskScore).GetMethod("GradeFor", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var grade = (char)method?.Invoke(null, new object[] { points })!;
        Assert.Equal(expectedGrade, grade);
    }

    /// <summary>
    /// Test: RiskScore.From throws on null report
    /// </summary>
    [Fact]
    public void From_ThrowsOnNullReport()
    {
        Assert.Throws<ArgumentNullException>(() => RiskScore.From(null!));
    }

    /// <summary>
    /// Test: Summary includes all severity counts > 0
    /// </summary>
    [Fact]
    public void Summary_IncludesAllNonZeroSeverityCounts()
    {
        var counts = new Dictionary<Severity, int> {
            { Severity.Critical, 2 },
            { Severity.High, 0 }, // Should not appear
            { Severity.Medium, 3 },
            { Severity.Low, 0 } // Should not appear
        };
        var score = new RiskScore(115, 'F', counts); // 2*40 + 3*5 = 95
        var summary = score.Summary();

        Assert.Contains("2 critical", summary);
        Assert.Contains("3 medium", summary);
        Assert.DoesNotContain("high", summary);
        Assert.DoesNotContain("0", summary);
    }

    /// <summary>
    /// Test: Summary returns "no findings" when all counts are zero or empty
    /// </summary>
    [Fact]
    public void Summary_ReturnsNoFindingsWhenEmpty()
    {
        var score1 = new RiskScore(0, 'A', new Dictionary<Severity, int>());
        var score2 = new RiskScore(0, 'A', new Dictionary<Severity, int> { { Severity.Low, 0 } });

        Assert.Contains("no findings", score1.Summary());
        Assert.Contains("no findings", score2.Summary());
    }
}
