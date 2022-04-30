using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using System.Security.Cryptography;
using System.Text;

namespace CompareServices
{
    internal class KMSHelper
    {
        private readonly AmazonKeyManagementServiceClient _client;

        public KMSHelper(string awsAccessKeyId, string awsSecretAccessKey, RegionEndpoint regionEndpoint)
        {
            _client = new AmazonKeyManagementServiceClient(awsAccessKeyId, awsSecretAccessKey, regionEndpoint);
        }

        public async Task<GenerateDataKeyResponse> CreateKeyAsync(string masterKeyId, DataKeySpec dataKeySpec)
        {
            return await _client.GenerateDataKeyAsync(new GenerateDataKeyRequest
            {
                KeyId = masterKeyId,
                KeySpec = dataKeySpec
            });
        }

        public string Encrypt(byte[] textToEncrypt, MemoryStream cipherText, MemoryStream key)
        {
            using var algorithm = Aes.Create();
            algorithm.Key = key.ToArray();

            using var msEncrypt = new MemoryStream();
            msEncrypt.WriteByte((byte)cipherText.Length);
            cipherText.CopyTo(msEncrypt);
            msEncrypt.Write(algorithm.IV, 0, algorithm.IV.Length);

            var encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV);

            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using var input = new MemoryStream(textToEncrypt);
            input.CopyTo(csEncrypt);
            csEncrypt.FlushFinalBlock();

            return Convert.ToBase64String(msEncrypt.ToArray());
        }

        public string Decrypt(byte[] textToDecrypt, MemoryStream key)
        {
            using var msDecrypt = new MemoryStream(textToDecrypt);
            var length = msDecrypt.ReadByte();
            var buffer = new byte[length];
            msDecrypt.Read(buffer, 0, length);

            using var algorithm = Aes.Create();
            algorithm.Key = key.ToArray();
            var iv = algorithm.IV;
            msDecrypt.Read(iv, 0, iv.Length);
            algorithm.IV = iv;

            var decryptor = algorithm.CreateDecryptor(algorithm.Key, algorithm.IV);

            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new MemoryStream();
            csDecrypt.CopyTo(srDecrypt);

            return Encoding.ASCII.GetString(srDecrypt.ToArray());
        }
    }
}
