namespace ecc_encryption.Models;

public class EncryptedData
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required byte[] Data { get; init; }

    /*public void SetData(List<string> list, string userSeed)
    {
        var data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(list));
        var result = AsymmetricCipher.EncryptWithDek(data, userSeed);
        Data = result.EncryptedData;
        EncryptedDek = result.EncryptedDek;
        DekIv = result.DekIv;
        KekSalt = result.KekSalt;
    }*/
}