using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace AESEncryption
{
    ///<summary>
    ///Class used to encrypt data
    ///</summary>
    ///<remarks>
    ///Based on AES encryption
    ///</remarks>
    ///
    public class Encryptor
    {
        private string password;
        private string salt;

        ///<summary>
        ///Set password and salt in constructor
        ///</summary>
        public Encryptor(string password, string salt)
        {
            this.password = password;
            this.salt = salt;
        }

        ///<summary>
        ///Encrypt string from input using AES
        ///</summary>
        public byte[] createKey()
        {
            int iterations = 1024;
            Rfc2898DeriveBytes rfc2898 = new System.Security.Cryptography.Rfc2898DeriveBytes(this.password, Encoding.UTF8.GetBytes(this.salt), iterations);
            byte[] key = rfc2898.GetBytes(32);
            String keyB64 = Convert.ToBase64String(key);
            System.Console.WriteLine("Key: " + keyB64);
            return key;
        }

        public AesManaged createCipher(byte[] key, String iv)
        {
            AesManaged aesCipher = new AesManaged();
            aesCipher.KeySize = 256;
            aesCipher.BlockSize = 128;
            aesCipher.Mode = CipherMode.CBC;
            aesCipher.Padding = PaddingMode.PKCS7;
            aesCipher.Key = key;
            if (iv != null)
            {
                aesCipher.IV = Convert.FromBase64String(iv);
                Console.WriteLine("IV:" + iv);
            }
            return aesCipher;
        }

        public String encrypt(AesManaged aesCipher, String plainText)
        {
            byte[] b = System.Text.Encoding.UTF8.GetBytes(plainText);
            ICryptoTransform encryptTransform = aesCipher.CreateEncryptor();
            byte[] ctext = encryptTransform.TransformFinalBlock(b, 0, b.Length);
            System.Console.WriteLine("IV:" + Convert.ToBase64String(aesCipher.IV));
            return Convert.ToBase64String(ctext);
        }

        public String decrypt(AesManaged aesCipher, String cipherText)
        {
            ICryptoTransform decryptTransform = aesCipher.CreateDecryptor();
            byte[] encrypted = Convert.FromBase64String(cipherText);
            byte[] plainText = decryptTransform.TransformFinalBlock(encrypted, 0, encrypted.Length);
            return Encoding.UTF8.GetString(plainText);
        }
       
    }
}
