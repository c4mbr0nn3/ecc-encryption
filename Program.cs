using System.Text;
using ecc_encryption.Models;

namespace ecc_encryption;

class Program
{
    public static void Main()
    {
        var credentialStore = new Dictionary<int, UserKeyCredential>(); // key = user id
        var encryptedDataStore = new Dictionary<Guid, EncryptedData>(); // key = data id
        var accessControlStore = new Dictionary<int, EncryptedDataAccessGrant>(); // key = user id

        // Example usage
        Console.WriteLine("Enter your id:");
        var id = Console.ReadLine();
        if (!int.TryParse(id, out var userId))
        {
            Console.WriteLine("Invalid id. Please enter a valid integer.");
            return;
        }

        Console.WriteLine("Enter your secret:");
        var secret = Console.ReadLine();
        if (string.IsNullOrEmpty(secret))
        {
            Console.WriteLine("Secret cannot be empty.");
            return;
        }

        if (!credentialStore.TryGetValue(userId, out var value))
        {
            var result = AsymmetricCipher.GenerateUserEcKeyPair(secret);
            var keyCredential = new UserKeyCredential
            {
                UserId = userId,
                PublicKey = result.PublicKey,
                EncryptedPrivateKey = result.EncryptedPrivateKey,
                Salt = result.Salt
            };
            value = keyCredential;
            credentialStore[userId] = value;
        }

        Console.WriteLine($"Public Key (Base64): {Convert.ToBase64String(value.PublicKey)}");
        Console.WriteLine($"Encrypted Private Key (Base64): {Convert.ToBase64String(value.EncryptedPrivateKey)}");
        Console.WriteLine($"Salt (Base64): {Convert.ToBase64String(value.Salt)}");

        Console.WriteLine("\nEnter sensitive data to encrypt:");
        var sensitiveData = Console.ReadLine();
        if (string.IsNullOrEmpty(sensitiveData))
        {
            Console.WriteLine("Sensitive data cannot be empty.");
            return;
        }

        // Encrypt the sensitive data using the public key
        var encryptionResult = AsymmetricCipher.EncryptDataWithPublicKey(sensitiveData, value.PublicKey);

        // Store the encrypted data
        encryptedDataStore[encryptionResult.Id] = encryptionResult;

        // Grant access to the user
        var accessGrant = new EncryptedDataAccessGrant
        {
            UserId = userId,
            DataId = encryptionResult.Id
        };

        accessControlStore[userId] = accessGrant;

        Console.WriteLine($"Encrypted Data (Base64): {Convert.ToBase64String(encryptionResult.Data)}");
        Console.WriteLine($"Encrypted DEK (Base64): {Convert.ToBase64String(encryptionResult.EncryptedDek)}");
        Console.WriteLine($"DEK IV (Base64): {Convert.ToBase64String(encryptionResult.DekIv)}");
        Console.WriteLine($"KEK Salt (Base64): {Convert.ToBase64String(encryptionResult.KekSalt)}");

        Console.WriteLine("\nTo decrypt the data, enter your secret again:");
        var decryptionSecret = Console.ReadLine();
        if (string.IsNullOrEmpty(decryptionSecret))
        {
            Console.WriteLine("Secret cannot be empty.");
            return;
        }

        if (!credentialStore.TryGetValue(userId, out var userKeyCredential))
        {
            Console.WriteLine("User key credential not found. Please generate a key pair first.");
            return;
        }

        if (!encryptedDataStore.TryGetValue(encryptionResult.Id, out var encryptedData))
        {
            Console.WriteLine("Encrypted data not found.");
            return;
        }

        try
        {
            var decryptedData =
                AsymmetricCipher.DecryptDataWithPrivateKey(encryptedData, decryptionSecret, userKeyCredential);
            Console.WriteLine($"Decrypted Data: {Encoding.UTF8.GetString(decryptedData)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption failed: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
    }
}