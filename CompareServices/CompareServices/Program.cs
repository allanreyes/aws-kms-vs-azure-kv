using Amazon;
using Amazon.KeyManagementService;
using Azure.Identity;
using CompareServices;
using System.Text;

// Using AWS

var awsAccessKeyId = "";
var awsSecretAccessKey = "";
var masterKeyId = "alias/test1";
var regionEndpoint = RegionEndpoint.USEast1;
var datakeySpec = DataKeySpec.AES_256;
var textToEncrypt = "Hello, AWS";

var kmsHelper = new KMSHelper(awsAccessKeyId, awsSecretAccessKey, regionEndpoint);
var awsKey = await kmsHelper.CreateKeyAsync(masterKeyId, datakeySpec);
var awsEncResult = kmsHelper.Encrypt(Encoding.UTF8.GetBytes(textToEncrypt), awsKey.CiphertextBlob, awsKey.Plaintext);
var awsDecResult = kmsHelper.Decrypt(Convert.FromBase64String(awsEncResult), awsKey.Plaintext);

Console.WriteLine($"AWS key id            : {awsKey.KeyId } \n\r");
Console.WriteLine($"AWS encryption result : {awsEncResult} \n\r");
Console.WriteLine($"AWS decryption result : {awsDecResult} \n\r");

// Using Azure

var cred = new DefaultAzureCredential();
var vaultUri = "https://{yourManagedHsm}.managedhsm.azure.net/";
textToEncrypt = "Hello, Azure";

var keyVaultHelper = new KeyVaultHelper(new Uri(vaultUri), cred);
var azurekey = await keyVaultHelper.CreateKeyAsync("test2", 256);
var azureEncResult = await keyVaultHelper.EncryptAsync(azurekey, textToEncrypt);
var azureDecResult = await keyVaultHelper.DecryptAsync(azurekey, azureEncResult.Ciphertext, azureEncResult.Iv);

Console.WriteLine($"Azure key id            : {azurekey.Id} \n\r");
Console.WriteLine($"Azure encryption result : {Convert.ToBase64String(azureEncResult.Ciphertext)} \n\r");
Console.WriteLine($"Azure decryption result : {azureDecResult} \n\r");

