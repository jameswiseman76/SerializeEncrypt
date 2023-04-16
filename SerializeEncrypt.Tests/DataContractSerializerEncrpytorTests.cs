// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DataContractSerializerEncrpytorTests.cs" company="www.jameswiseman.com">
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
//     Test for data contract serialization encryption and decryption.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace SerializeEncrypt.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass()]
    public class DataContractSerializerEncrpytorTests
    {
        #region Guard Tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Exception_Is_Thrown_When_Null_DataContractSerializer_Is_Passed_To_First_Constructor()
        {
            //Act
            try
            {
                var serializerEncryptor = new DataContractSerializerEncrpytor(null);
            }
            catch (ArgumentNullException argumentNullException)
            {
                Assert.AreEqual("Value cannot be null. (Parameter 'dataContractSerializerToDecorate')", argumentNullException.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Exception_Is_Thrown_When_Null_DataContractSerializer_Is_Passed_To_Second_Constructor()
        {
            //Act
            new DataContractSerializerEncrpytor(
                null,
                new byte[] { 1 },
                new byte[] { 1 },
                Aes.Create());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Exception_Is_Thrown_When_Null_cryptoServiceProvider_Is_Passed_To_Constructor()
        {
            //Act
            new DataContractSerializerEncrpytor(
                new DataContractSerializer(typeof(SerializableClass)),
                new byte[] { 1 },
                new byte[] { 1 },
                null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Exception_Is_Thrown_When_Null_encryptionKey_Is_Passed_To_Constructor()
        {
            //Act
            new DataContractSerializerEncrpytor(
                new DataContractSerializer(typeof(SerializableClass)),
                null,
                new byte[] { 1 },
                Aes.Create());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Exception_Is_Thrown_When_Null_encryptionIv_Is_Passed_To_Constructor()
        {
            //Act
            new DataContractSerializerEncrpytor(
                new DataContractSerializer(typeof(SerializableClass)),
                new byte[] { 1 },
                null,
                Aes.Create());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Exception_Is_Thrown_When_Null_newEncryptionKey_Is_Passed_To_Encrpytion_Override()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Field" };

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            serializerEncryptor.OverrideEncryption(
                null,
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 });

        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Exception_Is_Thrown_When_Null_newEncryptionIv_Is_Passed_To_Encrpytion_Override()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Field" };

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            serializerEncryptor.OverrideEncryption(
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 },
                null);

        }

        #endregion Guard Tests

        #region Encryption Tests

        [TestMethod]
        public void Output_Stream_Is_Written_To()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Output_Stream_Is_Written_To" };

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            // Setup a mock stream
            var mockStream = new Mock<Stream>();
            mockStream.SetupAllProperties();
            mockStream.Setup(stream => stream.Flush()).Callback(() => { int x = 0; });
            mockStream.SetupGet(stream => stream.CanWrite).Returns(true);

            // Act
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);

            // Assert
            mockStream.Verify(stream => stream.Flush(), Times.Exactly(3));  // Why is this 3?
            mockStream.Verify(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()), Times.AtLeastOnce);
        }

        [TestMethod]
        public void Identical_Encrpytion_Is_Applied_With_When_Reapplied_With_Default_Encryption()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Identical_Encrpytion_Is_Applied_With_When_Reapplied_With_Default_Encryption" };

            var streamWithEncryption = new List<byte>();
            var firstStreamWithEncryption = new List<byte>();
            var secondStreamWithEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            // Setup a mock stream
            var mockStream = new Mock<Stream>();
            mockStream.SetupAllProperties();
            mockStream.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));
            mockStream.SetupGet(stream => stream.CanWrite).Returns(true);

            // Act
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            firstStreamWithEncryption.AddRange(streamWithEncryption);

            streamWithEncryption.Clear();
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            secondStreamWithEncryption.AddRange(streamWithEncryption);

            // Assert
            Assert.IsTrue(firstStreamWithEncryption.SequenceEqual(secondStreamWithEncryption));
        }

        [TestMethod]
        public void Overriden_Encryption_Is_Applied_When_Key_And_Iv_Are_Overriden()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Overriden_Encryption_Is_Applied_When_Key_And_Iv_Are_Overriden" };

            var streamWithEncryption = new List<byte>();
            var streamWithDefaultEncryption = new List<byte>();
            var streamWithOverriddenEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            // Setup a mock stream
            var mockStream = new Mock<Stream>();
            mockStream.SetupAllProperties();
            mockStream.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));
            mockStream.SetupGet(stream => stream.CanWrite).Returns(true);

            // Act
            // Setup default encrpytion output
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithDefaultEncryption.AddRange(streamWithEncryption);
            streamWithEncryption.Clear();

            // Change and apply encrpytion
            serializerEncryptor.OverrideEncryption(
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 },
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 });
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithOverriddenEncryption.AddRange(streamWithEncryption);

            // Assert
            Assert.IsFalse(streamWithDefaultEncryption.SequenceEqual(streamWithOverriddenEncryption));
        }

        [TestMethod]
        public void Overriden_Encryption_Is_Applied_When_Algorithm_Is_Overridden_With_Constructor_Overload()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Overriden_Encryption_Is_Applied_When_Algorithm_Is_Overridden_With_Constructor_Overload" };

            var streamWithEncryption = new List<byte>();
            var streamWithDefaultEncryption = new List<byte>();
            var streamWithOverriddenEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            var defaultEncrpytionKey = serializerEncryptor.EncryptionKey;
            var defaultEncrpytionIv = serializerEncryptor.EncryptionIv;

            // Setup a mock stream
            var mockStream = new Mock<Stream>();
            mockStream.SetupAllProperties();
            mockStream.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));
            mockStream.SetupGet(stream => stream.CanWrite).Returns(true);

            // Act
            // Setup default encrpytion output
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithDefaultEncryption.AddRange(streamWithEncryption);
            streamWithEncryption.Clear();

            // Create a new serializer encryptor that applies a different algorithm
            var serializerOverriddenEncryptor = new DataContractSerializerEncrpytor(
                dataContractSerializer,
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                DES.Create());

            serializerOverriddenEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithOverriddenEncryption.AddRange(streamWithEncryption);

            // Assert
            Assert.IsFalse(streamWithDefaultEncryption.SequenceEqual(streamWithOverriddenEncryption));
            Assert.IsFalse(serializerOverriddenEncryptor.EncryptionKey.SequenceEqual(defaultEncrpytionKey));
            Assert.IsFalse(serializerOverriddenEncryptor.EncryptionIv.SequenceEqual(defaultEncrpytionIv));
        }

        [TestMethod]
        public void Overriden_Encryption_Is_Applied_When_Algorithm_Is_Overridden_With_OverrideEncryption_Method()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Overriden_Encryption_Is_Applied_When_Algorithm_Is_Overridden_With_OverrideEncryption_Method" };

            var streamWithEncryption = new List<byte>();
            var streamWithDefaultEncryption = new List<byte>();
            var streamWithOverriddenEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            var defaultEncrpytionKey = serializerEncryptor.EncryptionKey;
            var defaultEncrpytionIv = serializerEncryptor.EncryptionIv;

            // Setup a mock stream
            var mockStream = new Mock<Stream>();
            mockStream.SetupAllProperties();
            mockStream.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));
            mockStream.SetupGet(stream => stream.CanWrite).Returns(true);

            // Act
            // Setup default encrpytion output
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithDefaultEncryption.AddRange(streamWithEncryption);
            streamWithEncryption.Clear();

            // Change and apply encrpytion
            serializerEncryptor.OverrideEncryption(
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                DES.Create());

            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithOverriddenEncryption.AddRange(streamWithEncryption);

            // Assert
            Assert.IsFalse(streamWithDefaultEncryption.SequenceEqual(streamWithOverriddenEncryption));
            Assert.IsFalse(serializerEncryptor.EncryptionKey.SequenceEqual(defaultEncrpytionKey));
            Assert.IsFalse(serializerEncryptor.EncryptionIv.SequenceEqual(defaultEncrpytionIv));
        }

        [TestMethod]
        public void Default_Encrpytion_Can_Be_Restored_And_That_Algorithms_Are_Applied_Correctly()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "Default_Encrpytion_Can_Be_Restored_And_That_Algorithms_Are_Applied_Correctly" };

            var streamWithEncryption = new List<byte>();
            var streamWithDefaultEncryption = new List<byte>();
            var streamWithOverriddenEncryption = new List<byte>();
            var streamWithRestoredDefaultEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            // Setup a mock stream
            var mockStream = new Mock<Stream>();
            mockStream.SetupAllProperties();
            mockStream.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));
            mockStream.SetupGet(stream => stream.CanWrite).Returns(true);

            // Act
            // Setup default encrpytion output
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithDefaultEncryption.AddRange(streamWithEncryption);

            // Change and apply encrpytion
            serializerEncryptor.OverrideEncryption(
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                DES.Create());

            streamWithEncryption.Clear();
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithOverriddenEncryption.AddRange(streamWithEncryption);

            // Now change the encrpytion back
            serializerEncryptor.RestoreDefaultEncryption();
            streamWithEncryption.Clear();
            serializerEncryptor.WriteObjectEncrypted(mockStream.Object, serializableObject);
            streamWithRestoredDefaultEncryption.AddRange(streamWithEncryption);

            // Assert 
            // Our stream with default encrpytion should equal our stream with restored encryption
            Assert.IsTrue(streamWithDefaultEncryption.SequenceEqual(streamWithRestoredDefaultEncryption));

            // Both default and restored encryption schemes should be differed from the overriden one.
            Assert.IsFalse(streamWithDefaultEncryption.SequenceEqual(streamWithOverriddenEncryption));
            Assert.IsFalse(streamWithRestoredDefaultEncryption.SequenceEqual(streamWithOverriddenEncryption));
        }
        #endregion Encryption Tests

        #region Decryption Tests

        [TestMethod]
        public void We_Can_Decrypt_An_Encrypted_Stream()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "We_Can_Decrypt_An_Encrypted_Stream" };

            var streamWithEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            // Setup a mock stream for writing
            var mockStreamForWriting = new Mock<Stream>();
            mockStreamForWriting.SetupAllProperties();
            mockStreamForWriting.SetupGet(stream => stream.CanWrite).Returns(true);
            mockStreamForWriting.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));

            // Perform encryption to get encrypted byte array
            serializerEncryptor.WriteObjectEncrypted(mockStreamForWriting.Object, serializableObject);

            // New create a memory stream based on this, so we can pass it back into the Decryptor
            var streamForReading = new MemoryStream(streamWithEncryption.ToArray());

            // Act
            var decryptedObject = (SerializableClass)serializerEncryptor.ReadObjectEncrypted(streamForReading);

            // Assert
            Assert.AreEqual(serializableObject.Field, decryptedObject.Field);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void We_Cannot_Decrypt_A_Stream_That_Was_Encrypted_With_Different_Parameters()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "We_Cannot_Decrypt_A_Stream_That_Was_Encrypted_With_Different_Parameters" };

            var streamWithEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            // Setup a mock stream for writing
            var mockStreamForWriting = new Mock<Stream>();
            mockStreamForWriting.SetupAllProperties();
            mockStreamForWriting.SetupGet(stream => stream.CanWrite).Returns(true);
            mockStreamForWriting.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));

            // Perform encryption to get encrypted byte array
            serializerEncryptor.WriteObjectEncrypted(mockStreamForWriting.Object, serializableObject);

            // New create a memory stream based on this, so we can pass it back into the Decryptor
            var streamForReading = new MemoryStream(streamWithEncryption.ToArray());

            // Act
            // Override encryption and attempt to decrypt
            serializerEncryptor.OverrideEncryption(
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 },
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 });
            serializerEncryptor.ReadObjectEncrypted(streamForReading);
        }

        [TestMethod]
        public void We_Can_Decrypt_A_Stream_That_Was_Encrypted_With_Overridden_Encryption_Parameters()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "We_Can_Decrypt_A_Stream_That_Was_Encrypted_With_Overridden_Encryption_Parameters" };

            var streamWithEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerEncryptor = new DataContractSerializerEncrpytor(dataContractSerializer);

            // Setup a mock stream for writing
            var mockStreamForWriting = new Mock<Stream>();
            mockStreamForWriting.SetupAllProperties();
            mockStreamForWriting.SetupGet(stream => stream.CanWrite).Returns(true);
            mockStreamForWriting.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));

            serializerEncryptor.OverrideEncryption(
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 },
                new byte[] { 9, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 });

            // Perform encryption to get encrypted byte array
            serializerEncryptor.WriteObjectEncrypted(mockStreamForWriting.Object, serializableObject);

            // New create a memory stream based on this, so we can pass it back into the Decryptor
            var streamForReading = new MemoryStream(streamWithEncryption.ToArray());

            // Act
            var decryptedObject = (SerializableClass)serializerEncryptor.ReadObjectEncrypted(streamForReading);

            // Assert
            Assert.AreEqual(serializableObject.Field, decryptedObject.Field);
        }

        [TestMethod]
        public void We_Can_Decrypt_A_Stream_That_Was_Encrypted_With_Overridden_Encryption_Algorithm()
        {
            // Arrange
            var serializableObject = new SerializableClass { Field = "We_Can_Decrypt_A_Stream_That_Was_Encrypted_With_Overridden_Encryption_Algorithm" };

            var streamWithEncryption = new List<byte>();

            var dataContractSerializer = new DataContractSerializer(serializableObject.GetType());
            var serializerOverriddenEncryptor = new DataContractSerializerEncrpytor(
                dataContractSerializer,
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                DES.Create());

            // Setup a mock stream for writing
            var mockStreamForWriting = new Mock<Stream>();
            mockStreamForWriting.SetupAllProperties();
            mockStreamForWriting.SetupGet(stream => stream.CanWrite).Returns(true);
            mockStreamForWriting.Setup(stream => stream.Write(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
                .Callback(
                    (byte[] buffer, int offset, int count) =>
                        streamWithEncryption.AddRange(buffer));


            // Perform encryption to get encrypted byte array
            serializerOverriddenEncryptor.WriteObjectEncrypted(mockStreamForWriting.Object, serializableObject);

            // New create a memory stream based on this, so we can pass it back into the Decryptor
            var streamForReading = new MemoryStream(streamWithEncryption.ToArray());

            // Act
            var decryptedObject = (SerializableClass)serializerOverriddenEncryptor.ReadObjectEncrypted(streamForReading);

            // Assert
            Assert.AreEqual(serializableObject.Field, decryptedObject.Field);
        }
        #endregion  Decryption Tests
    }
}
