using RemoteTool.Video;

// Usage: RemoteTool.Bench   -> tile-JPEG numbers everywhere, plus H.264 (hardware/software) on Windows 11.
Console.WriteLine($"{Environment.OSVersion}  cores={Environment.ProcessorCount}  {CodecBenchmark.Resolution}, 45 frames/scenario (set BENCH_1080=1 for 1920x1080)");
var results = CodecBenchmark.Run(OperatingSystem.IsWindows() ? () => H264Support.CreateEncoder(int.Parse(CodecBenchmark.Resolution.Split('x')[0]), int.Parse(CodecBenchmark.Resolution.Split('x')[1]), 30, 2500, out _) : null);
CodecBenchmark.Print(results, Console.Out);
if (!OperatingSystem.IsWindows()) Console.WriteLine("\n(H.264 rows need Windows 11 + Media Foundation: run this tool there.)");
