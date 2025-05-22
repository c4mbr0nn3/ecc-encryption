namespace ecc_encryption.Models;

public class UserKeyCredential
{
    public int UserId { get; set; }
    public byte[] PublicKey { get; set; }
    public byte[] EncryptedPrivateKey { get; set; }
    public byte[] Salt { get; set; }
}