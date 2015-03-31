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
        public string Encrypt(string textToEncrypt)
        {
            byte[] encryptedBytes = null;
            byte[] saltBytes = FromHex(this.salt);
            byte[] bytesToBeEncrypted = System.Text.Encoding.Unicode.GetBytes(textToEncrypt);
            byte[] passwordBytes = System.Text.Encoding.Unicode.GetBytes(this.password);

            using (MemoryStream ms = new MemoryStream())
            {
                //using (RijndaelManaged AES = new RijndaelManaged())
                using (AesManaged AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1024);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (CryptoStream cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }

                    encryptedBytes = ms.ToArray();
                }
            }

            return BitConverter.ToString(encryptedBytes).Replace("-", string.Empty).ToLower();
        }

        ///<summary>
        ///Convert hex string to byte array
        ///</summary>
        private byte[] FromHex(string hex)
        {
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return raw;
        }
    }
}
