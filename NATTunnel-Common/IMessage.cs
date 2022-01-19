using System.IO;

namespace NATTunnel.Common
{
    /// <summary>
    /// Interface for various message types.
    /// </summary>
    public interface IMessage
    {
        /// <summary>
        /// Sends all data from this object to the given <paramref name="writer"/>.
        /// </summary>
        /// <param name="writer">The <see cref="BinaryWriter"/> to send data to.</param>
        void Serialize(BinaryWriter writer);
        /// <summary>
        /// Reads all data from the given <paramref name="reader"/> into this object.
        /// </summary>
        /// <param name="reader">The <see cref="BinaryReader"/> to read data from.</param>
        void Deserialize(BinaryReader reader);
    }
}
