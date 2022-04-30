using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Text;

namespace CompareServices
{
    internal class KeyVaultHelper
    {
        private readonly KeyClient _client;
        private readonly TokenCredential _tokenCredential;
        private int _keySize;

        public KeyVaultHelper(Uri vaultUri, TokenCredential tokenCredential)
        {
            _tokenCredential = tokenCredential;
            _client = new KeyClient(vaultUri, tokenCredential);
        }

        public async Task<KeyVaultKey> CreateKeyAsync(string name, int keySize)
        {
            var key = await _client.CreateOctKeyAsync(new CreateOctKeyOptions(name, true) { KeySize = keySize });
            _keySize = keySize;
            return key;
        }

        public async Task<EncryptResult> EncryptAsync(KeyVaultKey key, string textToEncrypt)
        {
            var cryptoClient = new CryptographyClient(key.Id, _tokenCredential);
            return await cryptoClient.EncryptAsync($"A{_keySize}CBC", Encoding.UTF8.GetBytes(textToEncrypt));
        }

        public async Task<string> DecryptAsync(KeyVaultKey key, byte[] cipherText, byte[] iv)
        {
            var cryptoClient = new CryptographyClient(key.Id, _tokenCredential);
            var result = await cryptoClient.DecryptAsync(GetDecryptParameters(cipherText, iv));
            return Encoding.Default.GetString(result.Plaintext);
        }

        private DecryptParameters GetDecryptParameters(byte[] cipherText, byte[] iv)
        {
            return _keySize switch
            {
                128 => DecryptParameters.A128CbcParameters(cipherText, iv),
                192 => DecryptParameters.A192CbcParameters(cipherText, iv),
                _ => DecryptParameters.A256CbcParameters(cipherText, iv),
            };
        }

    }
}
