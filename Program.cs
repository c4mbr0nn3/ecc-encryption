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
        // TODO: missing dek
        var encryptionResult = AsymmetricCipher.EncryptDataWithPublicKey(value.UserId, value.PublicKey, sensitiveData);
        var encryptedData = new EncryptedData
        {
            Data = encryptionResult
        };

        // Store the encrypted data
        encryptedDataStore[encryptedData.Id] = encryptedData;

        // grant access to the user
        var accessGrant = new EncryptedDataAccessGrant
        {
            UserId = userId,
            DataId = encryptedData.Id
        };

        accessControlStore[userId] = accessGrant;

        Console.WriteLine($"Encrypted Data (Base64): {Convert.ToBase64String(encryptedData.Data)}");

        // // In a real application, the salt would be stored in the database
        // // It should be generated once per user and saved
        // var salt = Cipher.GenerateRandomSalt();
        // Console.WriteLine($"Generated salt (Base64): {Convert.ToBase64String(salt)}");
        //
        // // Encrypt the sensitive data using a public key derived from the password
        // var encryptedData = Cipher.EncryptWithPassword(sensitiveData, password, salt);
        // Console.WriteLine($"\nEncrypted data (Base64): {Convert.ToBase64String(encryptedData)}");
        //
        // // Later, decrypt the data using the same password
        // Console.WriteLine("\nDecrypting with the same password...");
        // var decryptedData = Cipher.DecryptWithPassword(encryptedData, password, salt);
        // Console.WriteLine($"Decrypted: {decryptedData}");
        //
        // // What happens with a wrong password?
        // Console.WriteLine("\nTrying with incorrect password:");
        // try
        // {
        //     var wrongDecryption = Cipher.DecryptWithPassword(encryptedData, password + "wrong", salt);
        //     Console.WriteLine($"Decrypted (should not see this): {wrongDecryption}");
        // }
        // catch (Exception ex)
        // {
        //     Console.WriteLine($"Decryption failed as expected: {ex.Message}");
        // }
    }
}