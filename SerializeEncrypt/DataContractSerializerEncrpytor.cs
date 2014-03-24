// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DataContractSerializerEncrpytor.cs" company="www.jameswiseman.com">
// This license governs use of the accompanying software. If you use the software, you
// accept this license. If you do not accept the license, do not use the software.
//
// 1. Definitions
// The terms "reproduce," "reproduction," "derivative works," and "distribution" have the
// same meaning here as under U.S. copyright law.
// A "contribution" is the original software, or any additions or changes to the software.
// A "contributor" is any person that distributes its contribution under this license.
// "Licensed patents" are a contributor's patent claims that read directly on its contribution.
//
// 2. Grant of Rights
// (A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution or any derivative works that you create.
// (B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution in the software or derivative works of the contribution in the software.
//
// 3. Conditions and Limitations
// (A) No Trademark License- This license does not grant you rights to use any contributors' name, logo, or trademarks.
// (B) If you bring a patent claim against any contributor over patents that you claim are infringed by the software, your patent license from such contributor to the software ends automatically.
// (C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and attribution notices that are present in the software.
// (D) If you distribute any portion of the software in source code form, you may do so only under this license by including a complete copy of this license with your distribution. If you distribute any portion of the software in compiled or object code form, you may only do so under a license that complies with this license.
// (E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement.
// </copyright>
// <summary>
//     Provide data contract serialization encryption and decryption.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace SerializeEncrypt
{
    using System;
    using System.Collections.ObjectModel;
    using System.IO;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;

    /// <summary>
    /// Class to serialize and encrypt a data contact.
    /// </summary>
    public sealed class DataContractSerializerEncrpytor
    {
        /// <summary>
        /// The default encryption key
        /// </summary>
        private static readonly byte[] DefaultEncryptionKey =
        {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 
            1, 2
        };

        /// <summary>        
        /// The default encryption Initialization Vector
        /// </summary>
        private static readonly byte[] DefaultEncryptionIv = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };

        /// <summary>
        /// The decorated data contract serializer
        /// </summary>
        private readonly DataContractSerializer decoratedDataContractSerializer;

        /// <summary>
        /// The current encryption key
        /// </summary>
        private byte[] encryptionKey = DefaultEncryptionKey;

        /// <summary>
        /// The current encryption Initialization Vector
        /// </summary>
        private byte[] encryptionIv = DefaultEncryptionIv;

        /// <summary>
        /// The crypto service provider
        /// </summary>
        private SymmetricAlgorithm cryptoServiceProvider = new AesCryptoServiceProvider();

        /// <summary>
        /// Initializes a new instance of the <see cref="DataContractSerializerEncrpytor"/> class.
        /// </summary>
        /// <param name="dataContractSerializerToDecorate">The data contract serializer.</param>
        public DataContractSerializerEncrpytor(DataContractSerializer dataContractSerializerToDecorate)
        {
            if (dataContractSerializerToDecorate == null)
            {
                throw new ArgumentNullException("dataContractSerializerToDecorate");
            }

            this.decoratedDataContractSerializer = dataContractSerializerToDecorate;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DataContractSerializerEncrpytor" /> class.
        /// </summary>
        /// <param name="dataContractSerializerToDecorate">The data contract serializer.</param>
        /// <param name="encryptionKey">The encryption key.</param>
        /// <param name="encryptionIv">The encryption iv.</param>
        /// <param name="cryptoServiceProvider">The crypto service provider.</param>
        /// <exception cref="System.ArgumentNullException">
        /// dataContractSerializerToDecorate
        /// or
        /// encryptionIv
        /// or
        /// cryptoServiceProvider
        /// or
        /// encryptionIv
        /// </exception>
        public DataContractSerializerEncrpytor(
            DataContractSerializer dataContractSerializerToDecorate,
            byte[] encryptionKey,
            byte[] encryptionIv,
            SymmetricAlgorithm cryptoServiceProvider)
        {
            if (dataContractSerializerToDecorate == null)
            {
                throw new ArgumentNullException("dataContractSerializerToDecorate");
            }

            if (encryptionKey == null)
            {
                throw new ArgumentNullException("encryptionIv");
            }

            if (cryptoServiceProvider == null)
            {
                throw new ArgumentNullException("cryptoServiceProvider");
            }

            if (encryptionIv == null)
            {
                throw new ArgumentNullException("encryptionIv");
            }

            this.decoratedDataContractSerializer = dataContractSerializerToDecorate;
            this.OverrideEncryption(encryptionKey, encryptionIv, cryptoServiceProvider);
        }

        /// <summary>
        /// Gets the encryption key.
        /// </summary>
        /// <value>
        /// The encryption key.
        /// </value>
        public ReadOnlyCollection<byte> EncryptionKey
        {
            get { return Array.AsReadOnly(this.encryptionKey); }
        }

        /// <summary>
        /// Gets the encryption Initialization Vector.
        /// </summary>
        /// <value>
        /// The encryption Initialization Vector.
        /// </value>
        public ReadOnlyCollection<byte> EncryptionIv
        {
            get { return Array.AsReadOnly(this.encryptionIv); }
        }

        /// <summary>
        /// Overrides the default encryption.
        /// </summary>
        /// <param name="newEncryptionKey">The new encryption key.</param>
        /// <param name="newEncryptionIv">The new encryption iv.</param>
        /// <param name="newCryptoServiceProvider">The new crypto service provider.</param>
        /// <exception cref="System.ArgumentNullException">
        /// New encryption key cannot be null and New encryption IV cannot be null.
        /// </exception>
        public void OverrideEncryption(
            byte[] newEncryptionKey,
            byte[] newEncryptionIv,
            SymmetricAlgorithm newCryptoServiceProvider = null)
        {
            if (newEncryptionKey == null)
            {
                throw new ArgumentNullException("newEncryptionKey");
            }

            if (newEncryptionIv == null)
            {
                throw new ArgumentNullException("newEncryptionIv");
            }

            this.encryptionKey = newEncryptionKey;
            this.encryptionIv = newEncryptionIv;
            this.cryptoServiceProvider = newCryptoServiceProvider ?? this.cryptoServiceProvider;
        }
        
        /// <summary>
        /// Restores the default encryption.
        /// </summary>
        public void RestoreDefaultEncryption()
        {
            this.cryptoServiceProvider = new AesCryptoServiceProvider();
            this.encryptionKey = DefaultEncryptionKey;
            this.encryptionIv = DefaultEncryptionIv;
        }

        /// <summary>
        /// Writes the object to an encrypted stream.
        /// </summary>
        /// <param name="destinationStream">The stream.</param>
        /// <param name="graph">The graph.</param>
        public void WriteObjectEncrypted(
            Stream destinationStream,
            object graph)
        {
            // now encrpt and write the form data
            using (var memoryStream = new MemoryStream())
            {
                // serialize the form data into a memory stream and point to the start of this stream
                this.decoratedDataContractSerializer.WriteObject(memoryStream, graph);
                memoryStream.Position = 0L;

                // to encrypt, we need to read back out from the stream, so feed it into a stremreader
                this.WriteEncryptedStream(destinationStream, memoryStream);
            }
        }

        /// <summary>
        /// Reads the object encrypted.
        /// </summary>
        /// <param name="sourceStream">The source stream.</param>
        /// <returns>Of object of the underlying serialization type</returns>
        public object ReadObjectEncrypted(Stream sourceStream)
        {
            using (var cryptoTransform = this.cryptoServiceProvider.CreateDecryptor(this.encryptionKey, this.encryptionIv))
            {
                using (var cryptoStream = new CryptoStream(sourceStream, cryptoTransform, CryptoStreamMode.Read))
                {
                    using (var cryptoStreamReader = new StreamReader(cryptoStream))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var memoryStreamWriter = new StreamWriter(memoryStream))
                            {
                                var decrypted = cryptoStreamReader.ReadToEnd();
                                memoryStreamWriter.Write(decrypted);
                                memoryStreamWriter.Flush();
                                memoryStream.Position = 0L;

                                return this.decoratedDataContractSerializer.ReadObject(memoryStream);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Writes the encrypted stream from a given memory stream
        /// </summary>
        /// <param name="destinationStream">The file stream.</param>
        /// <param name="memoryStream">The memory stream.</param>
        private void WriteEncryptedStream(
            Stream destinationStream,
            Stream memoryStream)
        {
            using (var memoryStreamReader = new StreamReader(memoryStream))
            {
                // setup the crytographic provider and transformer
                using (var cryptoTransform = this.cryptoServiceProvider.CreateEncryptor(this.encryptionKey, this.encryptionIv))
                {
                    // now create the crypto stream to which we will write
                    using (var cryptoStream = new CryptoStream(destinationStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        // and now the stream writer that will do the physical file write based on the crypto stream
                        using (var cryptoStreamWriter = new StreamWriter(cryptoStream))
                        {
                            // remember the memoryStreamReader? We use it here to read to the end
                            var dataToEncrypt = memoryStreamReader.ReadToEnd();
                            cryptoStreamWriter.Write(dataToEncrypt);

                            // Flush the stream writer. So all buffered data get written to the underlying device.
                            cryptoStreamWriter.Flush();
                        }
                    }
                }
            }
        }
    }
}
