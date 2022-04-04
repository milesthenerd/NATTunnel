using System;

namespace NATTunnel.Common;

public class TokenBucket
{
    /// <summary>
    /// Requests data from a parent bucket as well.
    /// </summary>
    public readonly TokenBucket Parent;

    /// <summary>
    /// The rate in bytes per second
    /// </summary>
    public int RateBytesPerSecond;

    /// <summary>
    /// The size of the bucket, also the amount of data we can send at an unlimited rate.
    /// </summary>
    public int TotalBytes;

    //TODO: comment
    private int currentBytesPrivate;

    /// <summary>
    /// The current amount of bytes we can send
    /// </summary>
    public int CurrentBytes
    {
        get
        {
            Update();
            if ((Parent == null) || (Parent.CurrentBytes >= currentBytesPrivate))
                return currentBytesPrivate;

            return Parent.CurrentBytes;
        }
    }
    private long lastUpdateTime;

    public TokenBucket(int rateBytesPerSecond, int totalBytes, TokenBucket parent = null)
    {
        Parent = parent;
        RateBytesPerSecond = rateBytesPerSecond;
        TotalBytes = totalBytes;
    }

    private void Update()
    {
        //First call, set the buffer full
        if (lastUpdateTime == 0)
        {
            currentBytesPrivate = TotalBytes;
            lastUpdateTime = DateTime.UtcNow.Ticks;
            return;
        }

        long currentTime = DateTime.UtcNow.Ticks;
        long timeDelta = currentTime - lastUpdateTime;

        //Only update once per millisecond
        if (timeDelta < TimeSpan.TicksPerMillisecond)
            return;

        long newBytes = (RateBytesPerSecond * timeDelta) / TimeSpan.TicksPerSecond;
        currentBytesPrivate += (int)newBytes;
        currentBytesPrivate = currentBytesPrivate.LimitTo(TotalBytes);

        if (newBytes > 0)
            lastUpdateTime = currentTime;
    }

    public void Take(int bytes)
    {
        Parent?.Take(bytes);
        currentBytesPrivate -= bytes;
    }
}