using Cryptography.ECDSA;
using System;
using System.Security.Cryptography;
using System.Text;

namespace eos_ecc.entity;

public class KeyUtils
{
    public static string CheckEncode(byte[] keyBuffer, string keyType = null) 
    {
        if (keyType == "sha256")
        {
            var checksum = SHA256x2(keyBuffer).Take(4).ToArray();
            return Base58Encode([.. keyBuffer, .. checksum]);
        }
        else 
        {
            byte[] check = [.. keyBuffer];
            if (keyType is not null) 
            {
                check = [.. check, .. Encoding.UTF8.GetBytes(keyType)];
            }
            var checksum = Ripemd160Manager.GetHash(check).Take(4).ToArray();
            return Base58Encode([.. keyBuffer, .. checksum]);
        }
    }
    public static byte[] CheckDecode(string keyString, string keyType = null)
    {
        if (keyString == null)
        {
            throw new ArgumentNullException(nameof(keyString), "private key expected");
        }

        byte[] buffer = Base58Decode(keyString);

        byte[] checksum = buffer.Skip(buffer.Length - 4).ToArray();
        byte[] key = buffer.Take(buffer.Length - 4).ToArray();

        byte[] newCheck;

        if (keyType == "sha256x2")
        {
            newCheck = SHA256x2(key).Take(4).ToArray(); // WIF (legacy)
        }
        else
        {
            byte[] check = key;
            if (keyType != null)
            {
                check = key.Concat(Encoding.UTF8.GetBytes(keyType)).ToArray();
            }
            newCheck = Ripemd160Manager.GetHash(check).Take(4).ToArray(); // PVT
        }

        if (!checksum.SequenceEqual(newCheck))
        {
            throw new Exception($"Invalid checksum, {BitConverter.ToString(checksum).Replace("-", "")} != {BitConverter.ToString(newCheck).Replace("-", "")}");
        }

        return key;
    }

    private static byte[] Base58Decode(string input)
    {
        return Base58.Decode(input);
    }
    private static string Base58Encode(byte[] data)
    {
        return Base58.Encode(data);
    }

    private static byte[] SHA256x2(byte[] input)
    {
        return Sha256Manager.GetHash(Sha256Manager.GetHash(input));
    }
}
