using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using AESEncryption;
using System.Security.Cryptography;
using System.Text;

namespace UnitTestEncrypt
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestEncryptedIsNull()
        {
            Encryptor encryptor = new Encryptor("fw3qRExTDe4QSZb6", "f6018ff163dd9e3d");
            byte[] key = encryptor.createKey();


            AesManaged aesCipher = encryptor.createCipher(key, null);

            string encryptedText = encryptor.encrypt(aesCipher, "hello");

            Console.WriteLine("Encrypted: " + encryptedText);

            string iv = Convert.ToBase64String(aesCipher.IV);

            AesManaged aesCipher2 = encryptor.createCipher(key, iv);

            String decrypted = encryptor.decrypt(aesCipher2, encryptedText);

            Console.WriteLine("Decrypted: " + decrypted);
   
        }
    }
}
