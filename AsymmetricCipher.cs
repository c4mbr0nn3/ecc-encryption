using System.Security.Cryptography;
using ecc_encryption.Models;

namespace ecc_encryption;

public class AsymmetricCipher
{
    private const int SaltSize = 16; // 16 bytes = 128 bits
    private const int KeySizeInBytes = 32; // 32 bytes = 256 bits for AES-256
    private const int Pbkdf2Iterations = 100_000; // Adjust as needed
    private static readonly HashAlgorithmName Pbkdf2HashAlgorithm = HashAlgorithmName.SHA256;
    private static readonly ECCurve Curve = ECCurve.NamedCurves.nistP256; // NIST P-256 curve
    private const CipherMode CipherMode = System.Security.Cryptography.CipherMode.CBC;
    private const int EccKeySize = 256; // P-256 curve
    private const int AesKeySize = 256;

    public static UserEcKeyPairResult GenerateUserEcKeyPair(string userSecret)
    {
        var ecdh = ECDiffieHellman.Create();
        ecdh.KeySize = EccKeySize;
        var publicKeyBytes = ecdh.ExportSubjectPublicKeyInfo();
        var privateKeyBytes = ecdh.ExportECPrivateKey();

        var salt = GenerateRandomSalt();
        var key = DeriveKeyFromSeed(userSecret, salt);
        var encryptedPrivateKey = EncryptWithAes(privateKeyBytes, key);

        var result = new UserEcKeyPairResult
        {
            PublicKey = publicKeyBytes,
            EncryptedPrivateKey = encryptedPrivateKey.EncryptedData,
            Salt = salt
        };

        return result;
    }

    public static byte[] EncryptDataWithPublicKey(int userId, byte[] publicKey, string sensitiveData)
    {
        throw new NotImplementedException();
    }


    private static byte[] GenerateRandomSalt()
    {
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[SaltSize];
        rng.GetBytes(salt);
        return salt;
    }

    private static byte[] DeriveKeyFromSeed(string seed, byte[] salt)
    {
        if (string.IsNullOrEmpty(seed))
            throw new ArgumentNullException(nameof(seed));
        if (salt is not { Length: SaltSize })
            throw new ArgumentException($"Salt must be {SaltSize} bytes.", nameof(salt));

        using var pbkdf2 = new Rfc2898DeriveBytes(seed, salt, Pbkdf2Iterations, Pbkdf2HashAlgorithm);
        return pbkdf2.GetBytes(KeySizeInBytes);
    }

    private static AesEncryptionResult EncryptWithAes(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.KeySize = AesKeySize;
        aes.Key = key;
        aes.Mode = CipherMode;
        aes.GenerateIV();
        var iv = aes.IV;

        using var encryptor = aes.CreateEncryptor(key, iv);
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
            Dek = key,
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

        byte[] iv = new byte[aesAlg.BlockSize / 8];
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

    /*
    public static (ECDiffieHellman ecdh, byte[] publicKeyBytes) DeriveKeyPairFromSeed(string userSeed, byte[] salt)
    {
        var derivedKey = DeriveKeyFromSeed(userSeed, salt);

        // Create the ECC key using the derived bytes as the private key
        var ecdh = ECDiffieHellman.Create();
        ecdh.KeySize = EccKeySize;

        // Create parameters for the NIST P-256 curve
        var parameters = new ECParameters
        {
            Curve = Curve,
            D = derivedKey
        };

        try
        {
            // this will generate public key from private key
            ecdh.ImportParameters(parameters);
        }
        catch (CryptographicException)
        {
            // If the derived bytes don't create a valid private key, adjust them slightly
            // TODO: check this
            derivedKey[0] = (byte)(derivedKey[0] ^ 0x01);
            parameters.D = derivedKey;
            ecdh.ImportParameters(parameters);
        }

        // Export the public key
        var publicKeyBytes = ecdh.ExportSubjectPublicKeyInfo();
        return (ecdh, publicKeyBytes);
    }

    public static EncryptionResult EncryptWithDek(byte[] data, string userSeed)
    {
        var salt = GenerateRandomSalt();

        var (_, publicKeyBytes) = DeriveKeyPairFromSeed(userSeed, salt);

        // Encrypt the data with AES and random DEK and IV
        byte[] dek;
        using (var aes = Aes.Create())
        {
            aes.GenerateKey();
            dek = aes.Key;
        }

        var aesEncryptionResult = EncryptWithAes(data, dek);
        var dekIv = aesEncryptionResult.DekIv;

        // Encrypt the DEK with the public key
        var encryptedDek = EncryptWithPublicKey(dek, publicKeyBytes);
    }

    private static EccEncryptionResult EncryptWithPublicKey(byte[] data, byte[] publicKeyBytes)
    {
        using var ephemeralEcdh = ECDiffieHellman.Create();
        ephemeralEcdh.KeySize = EccKeySize;
        var recipientEcdh = ECDiffieHellman.Create();
        recipientEcdh.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
        var sharedSecret = ephemeralEcdh.DeriveKeyMaterial(ephemeralEcdh.PublicKey);
        var aesKey = DeriveKeyFromSeed(Convert.ToBase64String(sharedSecret), sharedSecret);
        var ephemeralPublicKey = ephemeralEcdh.ExportSubjectPublicKeyInfo();

        // Encrypt the data with AES using the derived key
        var result = EncryptWithAes(data, aesKey);

        return new EccEncryptionResult
        {
            EncryptedData = result.EncryptedData,
            Dek = result.Dek,
            DekIv = result.DekIv,
            KekSalt = ephemeralPublicKey
        };
    }*/
}

/*public class EncryptionResult
{
    public byte[] EncryptedData { get; set; }
    public byte[] EncryptedDek { get; set; }
    public byte[] DekIv { get; set; }
    public byte[] KekSalt { get; set; }
}

public class EccEncryptionResult
{
    public byte[] EncryptedData { get; set; }
    public byte[] Dek { get; set; }
    public byte[] DekIv { get; set; }
    public byte[] KekSalt { get; set; }
}*/