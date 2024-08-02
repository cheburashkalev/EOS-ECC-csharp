using eos_ecc.entity;

namespace eos_ecc;

public class ApiCommon
{
    public static bool VerifySignature(string signature, string data, string pubkey)
    {
        return Signature.From(signature).Verify(data, pubkey);
    }
    public static string SignData( string data, string privatekey)
    {
        return Signature.Sign(data, privatekey).ToString();
        //return Signature.From(signature).Verify(data, pubkey);
    }
}
