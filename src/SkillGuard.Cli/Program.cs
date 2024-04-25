using System.CommandLine;
using SkillGuard.Cli;
using SkillGuard.Core;
using SkillGuard.Rules;

var pathArgument = new Argument<string>("path", () => ".", "File or directory to scan");
var formatOption = new Option<string>(["--format", "-f"], () => "console", "Output format: console or sarif");
var outputOption = new Option<string?>(["--output", "-o"], "Write report to file instead of stdout");
var failOnOption = new Option<string>("--fail-on", () => "high", "Minimum severity that causes a non-zero exit: note, low, medium, high, critical, never");
var disableOption = new Option<string[]>("--disable", "Rule ids to disable") { AllowMultipleArgumentsPerToken = true };
var allowHostOption = new Option<string[]>("--allow-host", "Additional allowed egress hosts") { AllowMultipleArgumentsPerToken = true };
var noColorOption = new Option<bool>("--no-color", "Disable ANSI colors in console output");

var scanCommand = new Command("scan", "Scan skill and instruction files for security issues")
{
    pathArgument, formatOption, outputOption, failOnOption, disableOption, allowHostOption, noColorOption
};
scanCommand.SetHandler(context =>
{
    var path = context.ParseResult.GetValueForArgument(pathArgument);
    var format = context.ParseResult.GetValueForOption(formatOption)!;
    var output = context.ParseResult.GetValueForOption(outputOption);
    var failOn = context.ParseResult.GetValueForOption(failOnOption)!;
    var disabled = context.ParseResult.GetValueForOption(disableOption) ?? [];
    var allowHosts = context.ParseResult.GetValueForOption(allowHostOption) ?? [];
    var noColor = context.ParseResult.GetValueForOption(noColorOption);
    context.ExitCode = ScanRunner.Run(path, format, output, failOn, disabled, allowHosts, noColor);
});

var rulesCommand = new Command("rules", "List available rules");
rulesCommand.SetHandler(() =>
{
    foreach (var rule in RuleCatalog.CreateDefaultRules())
        Console.WriteLine($"{rule.Id}  {ConsoleReporter.SeverityLabel(rule.DefaultSeverity),-8}  {rule.Name}: {rule.Description}");
});

var root = new RootCommand("skill-guard: static security scanner for agent skill and instruction files");
root.AddCommand(scanCommand);
root.AddCommand(rulesCommand);
return await root.InvokeAsync(args);
