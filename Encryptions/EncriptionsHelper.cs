using System.Security.Cryptography;
using System.Text;

namespace Security
{
    public static class EncriptionsHelper
    {
        private static byte[] SaltBytes = new byte[] { 9, 9, 8, 8, 8, 8, 9, 9 };

        #region MD5
        public static string EncryptMD5(string plainText, string secretKey)
        {
            byte[] computeHash;
            byte[] toEncryptBytes = UTF8Encoding.UTF8.GetBytes(plainText);

            MD5 hashMD5 = MD5.Create();
            computeHash = hashMD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(secretKey));
            hashMD5.Clear();

            TripleDES tripleDES = TripleDES.Create();
            tripleDES.Key = computeHash;
            tripleDES.Mode = CipherMode.ECB;
            tripleDES.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = tripleDES.CreateEncryptor();
            byte[] encryptedResult = encryptor.TransformFinalBlock(toEncryptBytes, 0, toEncryptBytes.Length);
            tripleDES.Clear();

            return Convert.ToBase64String(encryptedResult, 0, encryptedResult.Length);
        }

        public static string DecryptMD5(string encryptedText, string secretKey)
        {
            byte[] computeHash;
            byte[] toEncryptBytes = Convert.FromBase64String(encryptedText);

            MD5 hashMD5 = MD5.Create();
            computeHash = hashMD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(secretKey));
            hashMD5.Clear();

            TripleDES tripleDES = TripleDES.Create();
            tripleDES.Key = computeHash;
            tripleDES.Mode = CipherMode.ECB;

            ICryptoTransform decryptor = tripleDES.CreateDecryptor();
            byte[] decryptedResult = decryptor.TransformFinalBlock(toEncryptBytes, 0, toEncryptBytes.Length);
            tripleDES.Clear();

            return UTF8Encoding.UTF8.GetString(decryptedResult);
        }

        #endregion

        #region SHA256 with SaltBytes
        public static string EncryptSHA256(string plainText, string secretKey)
        {
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(plainText);
            byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);

            secretKeyBytes = SHA256.Create().ComputeHash(secretKeyBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, secretKeyBytes);

            return Convert.ToBase64String(bytesEncrypted);
        }

        public static string DecryptSHA256(string encryptedText, string secretKey)
        {
            byte[] bytesToBeDecrypted = Convert.FromBase64String(encryptedText);
            byte[] secretKeyBytesDecrypt = Encoding.UTF8.GetBytes(secretKey);

            secretKeyBytesDecrypt = SHA256.Create().ComputeHash(secretKeyBytesDecrypt);

            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, secretKeyBytesDecrypt);

            return Encoding.UTF8.GetString(bytesDecrypted);
        }

        public static byte[] AES_Encrypt(byte[] bytesEncrypted, byte[] secretKeyBytes)
        {
            try
            {
                byte[]? encryptedBytes = null;

                using (MemoryStream ms = new MemoryStream())
                {
                    using Aes AES = Aes.Create();
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(secretKeyBytes, SaltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesEncrypted, 0, bytesEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }

                return encryptedBytes;
            }
            catch (Exception)
            {

                return Encoding.UTF8.GetBytes(string.Empty);
            }

        }

        public static byte[] AES_Decrypt(byte[] bytesDecrypted, byte[] secretKeyBytes)
        {
            try
            {
                byte[]? decryptedBytes = null;

                using (MemoryStream ms = new MemoryStream())
                {
                    using Aes AES = Aes.Create();
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(secretKeyBytes, SaltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesDecrypted, 0, bytesDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
                return decryptedBytes;
            }
            catch (Exception)
            {
                return Encoding.UTF8.GetBytes(string.Empty);
            }
        }
        #endregion

        #region AES
        public static string EncryptAES(string plainText, string secretKey)
        {
            var key = Encoding.UTF8.GetBytes(secretKey);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor(key, aes.IV);
            using var memory = new MemoryStream();
            using (var crypto = new CryptoStream(memory, encryptor, CryptoStreamMode.Write))
            using (var streamWriter = new StreamWriter(crypto))
            {
                streamWriter.Write(plainText);
            }

            var iv = aes.IV;

            var decryptedContent = memory.ToArray();

            var result = new byte[iv.Length + decryptedContent.Length];

            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

            return Convert.ToBase64String(result);
        }

        public static string DecryptAES(string encryptText, string secretKey)
        {
            string result;
            var fullCipher = Convert.FromBase64String(encryptText);

            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);

            var key = Encoding.UTF8.GetBytes(secretKey);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor(key, iv);
            using (var memory = new MemoryStream(cipher))
            {
                using var crypto = new CryptoStream(memory, decryptor, CryptoStreamMode.Read);
                using var streamReader = new StreamReader(crypto);
                result = streamReader.ReadToEnd();
            }

            return result;
        }
        #endregion
    }
}
