using System.Security.Cryptography;
using System.Text;

namespace CryptographyTool
{
    public class Cryptography
    {
        private const int MIN_KEY_SIZE = 16;
        private const int MAX_KEY_SIZE = 32;
        private const int IV_SIZE = 16;

        private readonly byte[] Key;
        private readonly byte[] IV;

        /// <summary>
        /// Overloaded constructor 
        /// </summary>
        /// <param name="key"> Encryption key </param>
        /// <param name="iv"> Initalization vector </param>
        /// <exception cref="ArgumentOutOfRangeException"> Key size or IV is outside the allowed range </exception>
        /// <exception cref="ArgumentNullException"> Key or iv are null or empty </exception>
        /// <exception cref="Exception"> Internal error </exception>
        public Cryptography(string key, string iv)
        {
            try
            {
                if (String.IsNullOrWhiteSpace(key)) throw new ArgumentNullException(nameof(key));
                if (String.IsNullOrWhiteSpace(iv)) throw new ArgumentNullException(nameof(iv));

                Key = Encoding.UTF8.GetBytes(key);
                IV = Encoding.UTF8.GetBytes(iv);

                if (Key.Length < MIN_KEY_SIZE || Key.Length > MAX_KEY_SIZE) throw new ArgumentOutOfRangeException(nameof(key));
                if (IV.Length != IV_SIZE) throw new ArgumentOutOfRangeException(nameof(iv));
            }
            catch (ArgumentOutOfRangeException error)
            {
                throw error;
            }
            catch (ArgumentNullException error)
            {
                throw error;
            }
            catch (Exception error)
            {
                throw error;
            }
        }

        /// <summary>
        /// Method to encrypt string content
        /// </summary>
        /// <param name="content"> Content to encrypt </param>
        /// <returns> Encrypted content </returns>
        /// <exception cref="ArgumentNullException"> Content null or empty </exception>
        /// <exception cref="Exception"> Internal error </exception>
        public string Encrypt(string content)
        {
            try
            {
                if (String.IsNullOrWhiteSpace(content)) throw new ArgumentNullException(nameof(content));

                using (Aes aes = Aes.Create())
                {
                    //Initialize algoritm keys
                    aes.Key = Key;
                    aes.IV = IV;

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter sw = new StreamWriter(cs))
                            {
                                //Write all data to the stream.
                                sw.Write(content);
                            }
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
            catch (ArgumentNullException error)
            {
                throw error;
            }
            catch (Exception error)
            {
                throw error;
            }
        }

        /// <summary>
        /// Method to decrypt content
        /// </summary>
        /// <param name="encryptedContent"> Ecrypted content </param>
        /// <returns> Decrypted content </returns>
        /// <exception cref="ArgumentNullException"> Content null or empty </exception>
        /// <exception cref="Exception"> Internal error </exception>
        public string Decrypt(string encryptedContent)
        {
            try
            {
                if (String.IsNullOrWhiteSpace(encryptedContent)) throw new ArgumentNullException(nameof(encryptedContent));
                byte[] bytes = Convert.FromBase64String(encryptedContent);

                using (Aes aes = Aes.Create())
                {
                    //Initialize algoritm keys
                    aes.Key = Key;
                    aes.IV = IV;

                    // Create an decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream ms = new MemoryStream(bytes))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader sr = new StreamReader(cs))
                            {
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (ArgumentNullException error)
            {
                throw error;
            }
            catch (Exception error)
            {
                throw error;
            }
        }
    }
}
