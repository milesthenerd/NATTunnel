namespace NATTunnel.Common;

public static class Extensions
{
    /// <summary>
    /// Limits <paramref name="number"/> to <paramref name="limit"/>.
    /// </summary>
    /// <param name="number">A number that should be limited.</param>
    /// <param name="limit">A number that <paramref name="number"/> should be limited to.</param>
    /// <returns>An <see cref="int"/> which is either <paramref name="number"/> or <paramref name="limit"/>.</returns>
    public static int LimitTo(this int number, int limit)
    {
        return number > limit ? limit : number;
    }

    /// <summary>
    /// Limits <paramref name="number"/> to <paramref name="limit"/>.
    /// </summary>
    /// <param name="number">A number that should be limited.</param>
    /// <param name="limit">A number that <paramref name="number"/> should be limited to.</param>
    /// <returns>A <see cref="long"/> which is either <paramref name="number"/> or <paramref name="limit"/>.</returns>
    public static long LimitTo(this long number, long limit)
    {
        return number > limit ? limit : number;
    }
}