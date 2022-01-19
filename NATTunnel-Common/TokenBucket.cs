using System;

namespace NATTunnel.Common
{
    public class TokenBucket
    {
        /// <summary>
        /// Requests data from a parent bucket as well.
        /// </summary>
        public TokenBucket parent;
        /// <summary>
        /// The rate in bytes per second
        /// </summary>
        public int rateBytesPerSecond;
        /// <summary>
        /// The size of the bucket, also the amount of data we can send at unlimited rate
        /// </summary>
        public int totalBytes;
        private int currentBytesPrivate;

        /// <summary>
        /// The current amount of bytes we can send
        /// </summary>
        public int currentBytes
        {
            get
            {
                Update();
                if (parent == null || parent.currentBytes >= currentBytesPrivate)
                    return currentBytesPrivate;

                return parent.currentBytes;
            }
        }
        private long lastUpdateTime;

        public TokenBucket(int rateBytesPerSecond, int totalBytes, TokenBucket parent = null)
        {
            this.parent = parent;
            this.rateBytesPerSecond = rateBytesPerSecond;
            this.totalBytes = totalBytes;
        }

        private void Update()
        {
            //First call, set the buffer full
            if (lastUpdateTime == 0)
            {
                currentBytesPrivate = totalBytes;
                lastUpdateTime = DateTime.UtcNow.Ticks;
                return;
            }

            long currentTime = DateTime.UtcNow.Ticks;
            long timeDelta = currentTime - lastUpdateTime;

            //Only update once per millisecond
            if (timeDelta < TimeSpan.TicksPerMillisecond)
                return;

            long newBytes = (rateBytesPerSecond * timeDelta) / TimeSpan.TicksPerSecond;
            currentBytesPrivate += (int)newBytes;
            currentBytesPrivate = currentBytesPrivate.LimitTo(totalBytes);

            if (newBytes > 0)
                lastUpdateTime = currentTime;
        }

        public void Take(int bytes)
        {
            parent?.Take(bytes);
            currentBytesPrivate -= bytes;
        }
    }
}