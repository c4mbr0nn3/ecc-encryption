using System.Security.Cryptography;
using System.Text;

namespace ecc_encryption;

public static class Cipher
{
    // Constants
    private const int SaltSize = 16; // 128 bits
    private const int Iterations = 100000; // Adjust based on security vs performance needs
    private const int EccKeySize = 256; // P-256 curve
    private const int AesKeySize = 256;

    // Generate a random salt for PBKDF2
    public static byte[] GenerateRandomSalt()
    {
        var salt = new byte[SaltSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    // Derive an ECC key pair from a password and salt
    private static (ECDiffieHellman ecdh, byte[] publicKeyBytes) DeriveKeyPairFromPassword(string password, byte[] salt)
    {
        // Derive key material from password using PBKDF2
        byte[] derivedBytes;
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
        {
            // We need at least 32 bytes for a 256-bit ECC key
            derivedBytes = pbkdf2.GetBytes(32);
        }

        // Create the ECC key using the derived bytes as the private key
        var ecdh = ECDiffieHellman.Create();
        ecdh.KeySize = EccKeySize;

        // Create parameters for the NIST P-256 curve
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = derivedBytes
        };

        try
        {
            // Import the parameters (this will generate public key from private key)
            ecdh.ImportParameters(parameters);
        }
        catch (CryptographicException)
        {
            // If the derived bytes don't create a valid private key, adjust them slightly
            derivedBytes[0] = (byte)(derivedBytes[0] ^ 0x01);
            parameters.D = derivedBytes;
            ecdh.ImportParameters(parameters);
        }

        // Export the public key
        var publicKeyBytes = ecdh.ExportSubjectPublicKeyInfo();

        return (ecdh, publicKeyBytes);
    }

    // Encrypt data using a password-derived public key
    public static byte[] EncryptWithPassword(string plainText, string password, byte[] salt)
    {
        // 1. Derive the ECC key pair from password
        var (_, publicKeyBytes) = DeriveKeyPairFromPassword(password, salt);

        // 2. Create a new ephemeral key pair for this encryption
        using var ephemeralEcdh = ECDiffieHellman.Create();
        ephemeralEcdh.KeySize = EccKeySize;

        // 3. Import the recipient's public key
        var recipientEcdh = ECDiffieHellman.Create();
        recipientEcdh.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

        // 4. Derive shared secret
        var sharedSecret = ephemeralEcdh.DeriveKeyMaterial(recipientEcdh.PublicKey);

        // 5. Derive an AES key from the shared secret
        byte[] aesKey;
        byte[] hmacKey;
        using (var kdf = new Rfc2898DeriveBytes(sharedSecret, salt, 1, HashAlgorithmName.SHA256))
        {
            aesKey = kdf.GetBytes(32); // 256 bits for AES-256
            hmacKey = kdf.GetBytes(32); // 256 bits for HMAC-SHA256
        }

        // 6. Get ephemeral public key to include with ciphertext
        var ephemeralPublicKey = ephemeralEcdh.ExportSubjectPublicKeyInfo();

        // 7. Encrypt data with AES using derived key
        byte[] encryptedData;
        byte[] iv;

        using (var aes = Aes.Create())
        {
            aes.KeySize = AesKeySize;
            aes.Key = aesKey;
            aes.GenerateIV();
            iv = aes.IV;

            using (var ms = new MemoryStream())
            {
                using (var encryptor = aes.CreateEncryptor())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
                    cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                    cs.FlushFinalBlock();
                    encryptedData = ms.ToArray();
                }
            }
        }

        // 8. Create a HMAC for authentication
        byte[] hmac;
        using (var hmacSha256 = new HMACSHA256(hmacKey))
        {
            using (var ms = new MemoryStream())
            {
                ms.Write(ephemeralPublicKey, 0, ephemeralPublicKey.Length);
                ms.Write(iv, 0, iv.Length);
                ms.Write(encryptedData, 0, encryptedData.Length);
                hmac = hmacSha256.ComputeHash(ms.ToArray());
            }
        }

        // 9. Construct the final package
        using (var finalPackage = new MemoryStream())
        {
            // Format: [salt][ephemeral public key length (4 bytes)][ephemeral public key][IV][encrypted data][HMAC]

            // Write salt
            finalPackage.Write(salt, 0, salt.Length);

            // Write ephemeral public key length and key
            var ephPubKeyLength = BitConverter.GetBytes(ephemeralPublicKey.Length);
            finalPackage.Write(ephPubKeyLength, 0, 4);
            finalPackage.Write(ephemeralPublicKey, 0, ephemeralPublicKey.Length);

            // Write IV
            finalPackage.Write(iv, 0, iv.Length);

            // Write encrypted data
            finalPackage.Write(encryptedData, 0, encryptedData.Length);

            // Write HMAC
            finalPackage.Write(hmac, 0, hmac.Length);

            return finalPackage.ToArray();
        }
    }

    // Decrypt data using a password-derived private key
    public static string DecryptWithPassword(byte[] encryptedPackage, string password, byte[] salt)
    {
        // 1. Derive the ECC key pair from password
        var (recipientEcdh, _) = DeriveKeyPairFromPassword(password, salt);

        // 2. Parse the encrypted package
        using var ms = new MemoryStream(encryptedPackage);
        // Skip the salt as it's provided separately
        ms.Position = SaltSize;

        // Read ephemeral public key length and key
        var ephPubKeyLengthBytes = new byte[4];
        ms.Read(ephPubKeyLengthBytes, 0, 4);
        var ephPubKeyLength = BitConverter.ToInt32(ephPubKeyLengthBytes, 0);

        var ephemeralPublicKey = new byte[ephPubKeyLength];
        ms.Read(ephemeralPublicKey, 0, ephPubKeyLength);

        // Read IV
        var iv = new byte[16]; // AES block size
        ms.Read(iv, 0, iv.Length);

        // Calculate encrypted data length
        var hmacLength = 32; // SHA-256 hash size
        var encryptedDataLength = ms.Length - ms.Position - hmacLength;

        // Read encrypted data
        var encryptedData = new byte[encryptedDataLength];
        ms.Read(encryptedData, 0, encryptedData.Length);

        // Read HMAC
        var hmac = new byte[hmacLength];
        ms.Read(hmac, 0, hmacLength);

        // 3. Import ephemeral public key
        using var ephemeralEcdh = ECDiffieHellman.Create();
        ephemeralEcdh.ImportSubjectPublicKeyInfo(ephemeralPublicKey, out _);

        // 4. Derive shared secret (same as during encryption)
        var sharedSecret = recipientEcdh.DeriveKeyMaterial(ephemeralEcdh.PublicKey);

        // 5. Derive AES and HMAC keys from shared secret
        byte[] aesKey;
        byte[] hmacKey;
        using (var kdf = new Rfc2898DeriveBytes(sharedSecret, salt, 1, HashAlgorithmName.SHA256))
        {
            aesKey = kdf.GetBytes(32);
            hmacKey = kdf.GetBytes(32);
        }

        // 6. Verify HMAC
        byte[] computedHmac;
        using (var hmacSha256 = new HMACSHA256(hmacKey))
        {
            using (var dataToVerify = new MemoryStream())
            {
                dataToVerify.Write(ephemeralPublicKey, 0, ephemeralPublicKey.Length);
                dataToVerify.Write(iv, 0, iv.Length);
                dataToVerify.Write(encryptedData, 0, encryptedData.Length);
                computedHmac = hmacSha256.ComputeHash(dataToVerify.ToArray());
            }
        }

        // Verify HMAC matches
        var hmacValid = true;
        for (var i = 0; i < hmac.Length; i++)
        {
            if (hmac[i] != computedHmac[i])
            {
                hmacValid = false;
                break;
            }
        }

        if (!hmacValid)
        {
            throw new CryptographicException("HMAC verification failed. Data may have been tampered with or password is incorrect.");
        }

        // 7. Decrypt the data with AES
        using (var aes = Aes.Create())
        {
            aes.KeySize = AesKeySize;
            aes.Key = aesKey;
            aes.IV = iv;

            using (var decryptor = aes.CreateDecryptor())
            using (var ms2 = new MemoryStream(encryptedData))
            using (var cs = new CryptoStream(ms2, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cs, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }
    }
}