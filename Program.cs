namespace ecc_encryption;

class Program
{
    public static void Main()
    {
        // Example usage
        Console.WriteLine("Enter your password:");
        var password = Console.ReadLine();

        Console.WriteLine("\nEnter sensitive data to encrypt:");
        var sensitiveData = Console.ReadLine();

        // In a real application, the salt would be stored in the database
        // It should be generated once per user and saved
        var salt = Cipher.GenerateRandomSalt();
        Console.WriteLine($"Generated salt (Base64): {Convert.ToBase64String(salt)}");

        // Encrypt the sensitive data using a public key derived from the password
        var encryptedData = Cipher.EncryptWithPassword(sensitiveData, password, salt);
        Console.WriteLine($"\nEncrypted data (Base64): {Convert.ToBase64String(encryptedData)}");

        // Later, decrypt the data using the same password
        Console.WriteLine("\nDecrypting with the same password...");
        var decryptedData = Cipher.DecryptWithPassword(encryptedData, password, salt);
        Console.WriteLine($"Decrypted: {decryptedData}");

        // What happens with a wrong password?
        Console.WriteLine("\nTrying with incorrect password:");
        try
        {
            var wrongDecryption = Cipher.DecryptWithPassword(encryptedData, password + "wrong", salt);
            Console.WriteLine($"Decrypted (should not see this): {wrongDecryption}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption failed as expected: {ex.Message}");
        }
    }
}