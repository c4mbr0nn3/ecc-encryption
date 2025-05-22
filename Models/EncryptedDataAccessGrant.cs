namespace ecc_encryption.Models;

public class EncryptedDataAccessGrant
{
    public int UserId { get; set; }
    public Guid DataId { get; set; }
    public byte[] EncryptedDek { get; set; }
}