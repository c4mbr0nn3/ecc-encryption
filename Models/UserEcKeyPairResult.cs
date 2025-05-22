namespace ecc_encryption.Models;

public class UserEcKeyPairResult
{
    public byte[] PublicKey { get; set; }
    public byte[] EncryptedPrivateKey { get; set; }
    public byte[] Salt { get; set; }
}