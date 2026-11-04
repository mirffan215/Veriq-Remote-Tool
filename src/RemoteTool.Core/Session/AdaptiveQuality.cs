namespace RemoteTool.Core.Session;

/// <summary>
/// Congestion control for the video loop. Slow sends first lower JPEG quality (to 40), then lower the frame rate
/// (to ~5 FPS); fast sends restore frame rate first, then quality (to 85).
/// </summary>
public sealed class AdaptiveQuality
{
    public const int MinQuality = 40, MaxQuality = 85;
    private readonly TimeSpan _baseInterval;
    private readonly TimeSpan _maxInterval = TimeSpan.FromMilliseconds(200);

    public AdaptiveQuality(int targetFps = 25)
    {
        _baseInterval = TimeSpan.FromMilliseconds(1000.0 / targetFps);
        Interval = _baseInterval;
    }

    public int Quality { get; private set; } = 70;
    public TimeSpan Interval { get; private set; }

    /// <summary>Feed the time it took to hand one frame to the network.</summary>
    public void Report(TimeSpan sendTime)
    {
        if (sendTime > Interval * 1.5)
        {
            if (Quality > MinQuality) Quality = Math.Max(MinQuality, Quality - 8);
            else Interval = TimeSpan.FromTicks(Math.Min(_maxInterval.Ticks, (long)(Interval.Ticks * 1.25)));
        }
        else if (sendTime < Interval / 2)
        {
            if (Interval > _baseInterval) Interval = TimeSpan.FromTicks(Math.Max(_baseInterval.Ticks, (long)(Interval.Ticks * 0.9)));
            else if (Quality < MaxQuality) Quality = Math.Min(MaxQuality, Quality + 2);
        }
    }
}
