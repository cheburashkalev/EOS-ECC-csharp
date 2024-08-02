using Org.BouncyCastle.Math.EC;
using System.Text.RegularExpressions;

namespace eos_ecc.entity;

public class PublicKey
{
    public byte[] Q { get; set; }
    public ECPoint ECPoint_D { get; set; }
    public static PublicKey FromString(string public_key, string pubkey_prefix = "EOS")
    {
        if (public_key == null)
            throw new ArgumentNullException(nameof(public_key));
        var match = Regex.Match(public_key, @"^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)$");
        if (!match.Success)
        {
            // Legacy
            var prefixMatch = new Regex("^" + pubkey_prefix);
            if (prefixMatch.IsMatch(public_key))
                public_key = public_key.Substring(pubkey_prefix.Length);

            return PublicKey.FromBuffer(KeyUtils.CheckDecode(public_key));
        }

        if (match.Groups.Count != 3)
            throw new ArgumentException("Expecting public key like: PUB_K1_base58pubkey..", nameof(public_key));

        var keyType = match.Groups[1].Value;
        var keyString = match.Groups[2].Value;

        if (keyType != "K1")
            throw new ArgumentException("K1 private key expected", nameof(public_key));
        return PublicKey.FromBuffer(KeyUtils.CheckDecode(keyString, keyType));
    }

    private static PublicKey FromBuffer(byte[] bytes)
    {
        return new PublicKey { Q = bytes };
    }
}