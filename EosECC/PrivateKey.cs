using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace eos_ecc.entity;

public class PrivateKey
{
    public byte[] D { get; set; }
    
    public static PrivateKey FromString(string privateStr)
    {
        if (privateStr == null || !(privateStr is string))
            throw new ArgumentException("privateStr");

        var match = Regex.Match(privateStr, @"^PVT_([A-Za-z0-9]+)_([A-Za-z0-9]+)$");

        if (!match.Success)
        {
            // legacy WIF - checksum includes the version
            var versionKey = KeyUtils.CheckDecode(privateStr, "sha256x2");
            var version = versionKey[0];
            if (version != 0x80)
                throw new Exception($"Expected version {0x80}, instead got {version}");
            var privateKey = PrivateKey.FromBuffer(versionKey[1..]);
            var keyType = "K1";
            var format = "WIF";
            return privateKey;
        }

        if (match.Groups.Count != 3)
            throw new Exception("Expecting private key like: PVT_K1_base58privateKey..");

        var keyTypeMatch = match.Groups[1].Value;
        var keyString = match.Groups[2].Value;

        if (keyTypeMatch != "K1")
            throw new Exception("K1 private key expected");

        var privateKeyDecoded = KeyUtils.CheckDecode(keyString, keyTypeMatch);
        var privateKeyResult = PrivateKey.FromBuffer(privateKeyDecoded);

        return privateKeyResult;
    }
    public PublicKey ToPublic()
    {
        X9ECParameters curveParams = CustomNamedCurves.GetByName("secp256k1");
        
        return new PublicKey { Q = curveParams.G.Multiply(new BigInteger(1,D)).GetEncoded(), ECPoint_D = curveParams.G.MultiplyEOS(new BigInteger(1,D)) };
    }
    private static PrivateKey FromBuffer(byte[] buf)
    {
        return new PrivateKey { D = buf };
    }
}
