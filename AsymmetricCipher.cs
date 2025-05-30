using System.Security.Cryptography;
using System.Text;
using ecc_encryption.Models;

namespace ecc_encryption;

public static class AsymmetricCipher
{
    private const int SaltSize = 16; // 16 bytes = 128 bits
    private const int KeySizeInBytes = 32; // 32 bytes = 256 bits for AES-256
    private const int Pbkdf2Iterations = 100_000; // Adjust as needed
    private static readonly HashAlgorithmName Pbkdf2HashAlgorithm = HashAlgorithmName.SHA256;
    private const CipherMode CipherMode = System.Security.Cryptography.CipherMode.CBC;
    private const int EccKeySize = 256; // P-256 curve
    private const int AesKeySize = 256;

    public static UserEcKeyPairResult GenerateUserEcKeyPair(string secret)
    {
        var ecdh = ECDiffieHellman.Create();
        ecdh.KeySize = EccKeySize;
        var publicKeyBytes = ecdh.ExportSubjectPublicKeyInfo();
        var privateKeyBytes = ecdh.ExportECPrivateKey();
        Console.WriteLine($"Public Key: {Convert.ToBase64String(publicKeyBytes)}");
        Console.WriteLine($"Private Key: {Convert.ToBase64String(privateKeyBytes)}");

        var salt = GenerateRandomSalt();
        var key = DeriveKeyFromSecret(secret, salt);
        var encryptedPrivateKey = EncryptWithAes(privateKeyBytes, key);

        var result = new UserEcKeyPairResult
        {
            PublicKey = publicKeyBytes,
            EncryptedPrivateKey = encryptedPrivateKey.EncryptedData,
            Salt = salt
        };

        return result;
    }

    public static EncryptedData EncryptDataWithPublicKey(string sensitiveData, byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length == 0)
            throw new ArgumentNullException(nameof(publicKey), "Public key cannot be null or empty.");

        if (string.IsNullOrEmpty(sensitiveData))
            throw new ArgumentNullException(nameof(sensitiveData), "Sensitive data cannot be null or empty.");

        if (!TryGetEcDiffieHellmanFromPublicKey(publicKey, out var recipientEcdh))
            throw new ArgumentException("Invalid public key format.", nameof(publicKey));

        // Encrypt the sensitive data with AES using random DEK and IV
        var sensitiveDataEncryptionResult = EncryptWithAes(Encoding.UTF8.GetBytes(sensitiveData));
        var encrytpionDek = sensitiveDataEncryptionResult.Dek;
        var dekIv = sensitiveDataEncryptionResult.DekIv;
        Console.WriteLine($"Dek: {Convert.ToBase64String(encrytpionDek)}");
        Console.WriteLine($"DekIv: {Convert.ToBase64String(dekIv)}");

        // Encrypt the DEK with the shared secret
        using var ephemeralEcdh = ECDiffieHellman.Create();
        ephemeralEcdh.KeySize = EccKeySize;
        var sharedSecret = ephemeralEcdh.DeriveKeyMaterial(recipientEcdh.PublicKey);
        Console.WriteLine($"Shared Secret: {Convert.ToBase64String(sharedSecret)}");
        var ephemeralPublicKey = ephemeralEcdh.ExportSubjectPublicKeyInfo();
        var aesKey = DeriveKeyFromSecret(Convert.ToBase64String(sharedSecret), ephemeralPublicKey);
        var encryptedDek = EncryptWithAes(encrytpionDek, aesKey);

        return new EncryptedData
        {
            Data = sensitiveDataEncryptionResult.EncryptedData,
            EncryptedDek = encryptedDek.EncryptedData,
            DekIv = dekIv,
            KekSalt = ephemeralPublicKey
        };
    }

    public static byte[] DecryptDataWithPrivateKey(EncryptedData encryptedData, string secret,
        UserKeyCredential userKeyCredential)
    {
        if (encryptedData == null)
            throw new ArgumentNullException(nameof(encryptedData), "Encrypted data cannot be null.");

        if (string.IsNullOrEmpty(secret))
            throw new ArgumentNullException(nameof(secret), "Secret cannot be null or empty.");

        if (userKeyCredential == null)
            throw new ArgumentNullException(nameof(userKeyCredential), "User key credential cannot be null.");

        // get private key from user key credential
        var salt = userKeyCredential.Salt;
        var key = DeriveKeyFromSecret(secret, salt);
        var privateKey = DecryptWithAes(userKeyCredential.EncryptedPrivateKey, key);
        Console.WriteLine($"Private Key: {Convert.ToBase64String(privateKey)}");

        // use private key to decrypt the DEK
        if (!TryGetEcDiffieHellmanFromPrivateKey(privateKey, out var privateEcdh))
            throw new ArgumentException("Invalid private key format.", nameof(userKeyCredential.EncryptedPrivateKey));
        // Import the ephemeral public key that was used during encryption
        if (!TryGetEcDiffieHellmanFromPublicKey(encryptedData.KekSalt, out var ephemeralPublicKeyEcdh))
            throw new ArgumentException("Invalid ephemeral public key format.");
        // Derive shared secret using private key + ephemeral public key
        var sharedSecret = privateEcdh.DeriveKeyMaterial(ephemeralPublicKeyEcdh.PublicKey);
        Console.WriteLine($"Shared Secret: {Convert.ToBase64String(sharedSecret)}");
        var aesKey = DeriveKeyFromSecret(Convert.ToBase64String(sharedSecret), encryptedData.KekSalt);
        var decryptedDek = DecryptWithAes(encryptedData.EncryptedDek, aesKey);
        Console.WriteLine($"Decrypted DEK: {Convert.ToBase64String(decryptedDek)}");
        if (decryptedDek.Length != KeySizeInBytes)
            throw new CryptographicException("Decrypted DEK has an invalid length.");
        // decrypt the sensitive data with the DEK
        var decryptedData = DecryptWithAes(encryptedData.Data, decryptedDek);
        return decryptedData;
    }

    private static bool TryGetEcDiffieHellmanFromPublicKey(byte[] publicKey, out ECDiffieHellman ecdh)
    {
        try
        {
            ecdh = ECDiffieHellman.Create();
            ecdh.ImportSubjectPublicKeyInfo(publicKey, out _);
            return true;
        }
        catch (CryptographicException)
        {
            ecdh = null;
            return false;
        }
    }

    private static bool TryGetEcDiffieHellmanFromPrivateKey(byte[] privateKey, out ECDiffieHellman ecdh)
    {
        try
        {
            ecdh = ECDiffieHellman.Create();
            ecdh.ImportECPrivateKey(privateKey, out _);
            return true;
        }
        catch (CryptographicException e)
        {
            ecdh = null;
            return false;
        }
    }

    private static byte[] GenerateRandomSalt()
    {
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[SaltSize];
        rng.GetBytes(salt);
        return salt;
    }

    private static byte[] DeriveKeyFromSecret(string secret, byte[] salt)
    {
        if (string.IsNullOrEmpty(secret))
            throw new ArgumentNullException(nameof(secret));

        using var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, Pbkdf2Iterations, Pbkdf2HashAlgorithm);
        return pbkdf2.GetBytes(KeySizeInBytes);
    }

    private static AesEncryptionResult EncryptWithAes(byte[] data, byte[]? key = null)
    {
        using var aes = Aes.Create();
        aes.KeySize = AesKeySize;
        aes.Mode = CipherMode;
        byte[] actualKey;
        if (key == null)
        {
            aes.GenerateKey();
            actualKey = aes.Key;
        }
        else if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentException($"Key must be {KeySizeInBytes} bytes long.", nameof(key));
        }
        else
        {
            actualKey = key;
            aes.Key = key;
        }

        aes.GenerateIV();
        var iv = aes.IV;

        using var encryptor = aes.CreateEncryptor(actualKey, iv);
        using var ms = new MemoryStream();
        ms.Write(iv, 0, iv.Length);
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            cs.Close();
        }

        return new AesEncryptionResult
        {
            EncryptedData = ms.ToArray(),
            Dek = actualKey,
            DekIv = iv
        };
    }

    private static byte[] DecryptWithAes(byte[] data, byte[] key)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.Mode = CipherMode.CBC;

        if (data == null || data.Length < aesAlg.BlockSize / 8)
            throw new ArgumentException("Encrypted data is too short to contain an IV.", nameof(data));

        var iv = new byte[aesAlg.BlockSize / 8];
        Buffer.BlockCopy(data, 0, iv, 0, iv.Length);
        aesAlg.IV = iv;

        using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        using var msDecrypt = new MemoryStream(data, iv.Length, data.Length - iv.Length);
        using var msPlainText = new MemoryStream();
        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        {
            csDecrypt.CopyTo(msPlainText);
        }

        return msPlainText.ToArray();
    }
}