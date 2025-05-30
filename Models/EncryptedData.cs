namespace ecc_encryption.Models;

public class EncryptedData
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required byte[] Data { get; init; }
    public required byte[] EncryptedDek { get; init; }
    public required byte[] DekIv { get; init; }
    public required byte[] KekSalt { get; init; }
}