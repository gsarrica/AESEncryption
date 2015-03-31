using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using AESEncryption;

namespace UnitTestEncrypt
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestEncryptedIsNull()
        {
            string testText = "Hello";
            string password = "efgfdvdfsdfdfdgyjh";
            string salt = "f2018ba157dd9f3d";

            Encryptor ecncryptor = new Encryptor(password, salt);
            string encryptedText = ecncryptor.Encrypt(testText);
            if (string.IsNullOrEmpty(encryptedText))
                throw new Exception("Encrypted text should not be null");

            Console.WriteLine(encryptedText);
        }
    }
}
