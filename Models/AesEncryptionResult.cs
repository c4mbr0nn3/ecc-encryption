namespace ecc_encryption.Models;

public class AesEncryptionResult
{
    public byte[] EncryptedData { get; set; }
    public byte[] Dek { get; set; }
    public byte[] DekIv { get; set; }
}