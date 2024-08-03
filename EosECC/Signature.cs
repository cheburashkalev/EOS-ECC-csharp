using Cryptography.ECDSA;
using ECDSA;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Diagnostics;
using System.Drawing;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using static System.Runtime.InteropServices.JavaScript.JSType;
using BigInteger = Org.BouncyCastle.Math.BigInteger;
using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace eos_ecc.entity;

public class Signature
{
    public System.Numerics.BigInteger R { get; private set; }
    public System.Numerics.BigInteger S { get; private set; }
    public int I { get; private set; }
    public byte[] buf;

    public Signature(System.Numerics.BigInteger r, System.Numerics.BigInteger s)
    {
        R = r;
        S = s;
        
    }

    public Signature(System.Numerics.BigInteger r, System.Numerics.BigInteger s, int i, byte[] buf)
    {
        R = r;
        S = s;
        I = i;
        this.buf = buf;
    }
    private string? signatureCache { get; set; }
    public override string ToString()
    {
        if (signatureCache is not null)
            return signatureCache;
        signatureCache = "SIG_K1_" + KeyUtils.CheckEncode(buf, "K1");
        return signatureCache;
    }
    public byte[] ToBuffer()
    {
        byte[] buf = new byte[65];
        buf[0] = (byte)I;
        byte[] rBytes = new BigInteger(R.ToString()).ToByteArray();
        //byte[] rBytes = R.ToByteArray();
        byte[] sBytes = new BigInteger(S.ToString()).ToByteArray();
        //byte[] sBytes = S.ToByteArray();

        if (rBytes.Length > 32)
        {
            Array.Copy(rBytes, rBytes.Length - 32, buf, 1, 32);
        }
        else
        {
            Array.Copy(rBytes, 0, buf, 33 - rBytes.Length, rBytes.Length);
        }

        if (sBytes.Length > 32)
        {
            Array.Copy(sBytes, sBytes.Length - 32, buf, 33, 32);
        }
        else
        {
            Array.Copy(sBytes, 0, buf, 65 - sBytes.Length, sBytes.Length);
        }

        return buf;
    }
    //public byte[] ToBuffer()
    //{
    //    byte[] buffer = new byte[65];
    //
    //    // Write 'i' as the first byte
    //    buffer[0] = (byte)I;
    //
    //    // Convert 'R' to a byte array and copy it to the buffer starting at position 1
    //    byte[] rBytes = R.ToByteArray();
    //    rBytes = rBytes.ToArray();
    //    //if (rBytes.Length > 32)
    //    //    throw new ArgumentException("R is too large to fit in 32 bytes");
    //
    //    Array.Copy(rBytes, 0, buffer, 1 + (32 - rBytes.Length), rBytes.Length);
    //
    //    // Convert 'S' to a byte array and copy it to the buffer starting at position 33
    //    byte[] sBytes = S.ToByteArray();
    //    sBytes = rBytes.ToArray();
    //    //if (sBytes.Length > 32)
    //    //    throw new ArgumentException("S is too large to fit in 32 bytes");
    //
    //    Array.Copy(sBytes, 0, buffer, 33 + (32 - sBytes.Length), sBytes.Length);
    //
    //    return buffer;
    //}

    public static Signature From(string signature)
    {
        var result = signature.Length != 130 ? FromStringOrThrow(signature) : null;
        if (result == null)
            throw new Exception("Invalid signature");
        return result;
    }

    public bool Verify(byte[] data, string pubkey)
    {
        var hash_data = Sha256Manager.GetHash(data);
        return VerifyHash(hash_data, pubkey);
    }

    public bool Verify(string data, string pubkey)
    {
        var row_data = Encoding.UTF8.GetBytes(data);
        return Verify(row_data, pubkey);
    }

    private bool VerifyHash(byte[] data, string pubkey)
    {
        var _pubkey = PublicKey.FromString(pubkey);

        ECDsaSigner eCDsaSigner = new ECDsaSigner();
        X9ECParameters curveParams = SecNamedCurves.GetByName("secp256k1");
        ECDomainParameters domainParams = new ECDomainParameters(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);
        var point = domainParams.Curve.DecodePoint(_pubkey.Q);

        var _r = new Org.BouncyCastle.Math.BigInteger(R.ToString());
        var _s = new Org.BouncyCastle.Math.BigInteger(S.ToString());
        eCDsaSigner.Init(forSigning: false, new ECPublicKeyParameters(point, domainParams));
        return eCDsaSigner.VerifySignature(data, _r, _s);
    }

    public static Signature Sign(string message, string privateKeyStr)
    {
        byte[] data = Encoding.UTF8.GetBytes(message);
        byte[] hashData = Sha256Manager.GetHash(data);
        PrivateKey privateKey = PrivateKey.FromString(privateKeyStr);
        return Signature.SignHash(hashData, privateKey);
    }

    public static Signature SignHash(byte[] dataSha256, PrivateKey privateKey)
    {
        if (dataSha256.Length != 32)
            throw new ArgumentException("dataSha256: 32 byte buffer required");

        ECDsaSigner eCDsaSigner = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        X9ECParameters curveParams = CustomNamedCurves.GetByName("secp256k1");
        
        ECDomainParameters domainParams = new ECDomainParameters(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);
        eCDsaSigner.Init(true, new ECPrivateKeyParameters(new Org.BouncyCastle.Math.BigInteger(privateKey.D), domainParams));
        int nonce = 0;
        int i = 0;
        System.Numerics.BigInteger r;
        System.Numerics.BigInteger s;
        while (true)
        {
            BigInteger[] result = eCDsaSigner.GenerateSignature(dataSha256,nonce);
            nonce++;
            var _r = result[0].ToByteArray();
            var _s = result[1].ToByteArray();

            var der = ToDER(_r, _s);
            var lenR = der[3];
            var lenS = der[5 + lenR];
            var e = new BigInteger(1, dataSha256);
            //System.Security.Cryptography.ECCurve.CreateFromFriendlyName("secp256k1")
            r = System.Numerics.BigInteger.Parse(result[0].ToString());
            s = System.Numerics.BigInteger.Parse(result[1].ToString());
            if (lenR == 32 && lenS == 32)
            {
                i = calcPubKeyRecoveryParam(curveParams, e, new Signature(r, s), privateKey.ToPublic().ECPoint_D);
                i += 4;
                i += 27;
                break;
            }
            if (nonce % 10 == 0)
            {
                Console.WriteLine("WARN: " + nonce + " attempts to find canonical signature");
            }
        }
        Signature signature = new Signature(r, s, i, []);
        signature = new Signature(r, s, i, signature.ToBuffer());
        return signature;
    }
    public static int calcPubKeyRecoveryParam(X9ECParameters curve, BigInteger e, Signature signature, ECPoint Q) 
    {
        for (var i = 0; i < 4; i++)
        {
            var Qprime = RecoverPubKey(curve, e, signature, i);
            if (Qprime.EqualsEOS(Q)) 
            {
                return i;
            }
        }
        throw new Exception("Unable to find valid recovery factor");
    }
    static public ECPoint multiplyTwo(BigInteger j, ECPoint x, BigInteger k, ECPoint point)
    {

        var i = Math.Max(j.BitLength, k.BitLength) - 1;
        var R = point.Curve.Infinity;
        var both = point.AddEOS(x);
        while (i >= 0)
        {
            
            var jBit = j.TestBit(i);
            var kBit = k.TestBit(i);
            R = R.TwiceEOS();
            if (jBit)
            {
                if (kBit)
                {
                    R = R.AddEOS(both);
                }
                else
                {
                    R = R.AddEOS(point);
                }
            }
            else if (kBit)
            {
                R = R.AddEOS(x);
            }
            --i;
        }
        return R;
    }
    public static (BigInteger x, BigInteger y) pointFromX(X9ECParameters curve,int isYOdd, BigInteger x)
    {
        var alpha = x.Pow(3).Add(curve.Curve.A.ToBigInteger().Multiply(x)).Add(curve.Curve.B.ToBigInteger()).Mod(curve.Curve.Field.Characteristic);
        var beta = alpha.ModPow(curve.Curve.Field.Characteristic.Add(BigInteger.One).ShiftRight(2), curve.Curve.Field.Characteristic);
        var y = beta;
        if (System.Numerics.BigInteger.Parse(beta.ToString()).IsEven ^ !(isYOdd >= 1))
        {
            y = curve.Curve.Field.Characteristic.Subtract(y);
        }
        return (x, y);
    }
    public static ECPoint RecoverPubKey(X9ECParameters curve, BigInteger e, Signature signature, int i)
    {
        Debug.Assert((i & 3) == i, "Recovery param is more than two bits");
        var Curve = curve.Curve;
        BigInteger n = curve.N;
        ECPoint G = curve.G;

        BigInteger r = new BigInteger(signature.R.ToString());
        BigInteger s = new BigInteger(signature.S.ToString());

        Debug.Assert(r.SignValue > 0 && r.CompareTo(n) < 0, "Invalid r value");
        Debug.Assert(s.SignValue > 0 && s.CompareTo(n) < 0, "Invalid s value");

        int isYOdd = (i & 1);
        int isSecondKey = (i >> 1);

        BigInteger x = isSecondKey == 1 ? r.Add(n) : r;

        var _pointFromX = pointFromX(curve,isYOdd, x);
        var R = Curve.CreatePoint(_pointFromX.x, _pointFromX.y);
        var nR = R.Multiply(n);
        Debug.Assert(Curve.Infinity == nR,"nR is not a valid curve point" );
        var eNeg = e.Negate().Mod(n);
        var rInv = r.ModInverse(n);

        var Q = multiplyTwo(s, G, eNeg, R);
        Q = Q.MultiplyEOS(rInv);
        // Q = Q.Multiply(rInv);//multiply(Curve, Q, rInv);

        //var Q = R.Multiply(s).Add(G.Multiply(eNeg)).Multiply(rInv);
        if (!Q.IsValidEOS()) 
        {
            throw new Exception("nu pizdetz");
        }
        //Curve.ValidatePoint(Q.XCoord.ToBigInteger(),Q.YCoord.ToBigInteger());
        //ECPoint R = curve.PointFromX(isYOdd, x);

        //ECPoint nR = R.Multiply(n);
        //Debug.Assert(curve.IsInfinity(nR), "nR is not a valid curve point");

        //BigInteger eNeg = e.Negate().Mod(n);

        //BigInteger rInv = r.ModInverse(n);

        //ECPoint Q = R.MultiplyTwo(s, G, eNeg).Multiply(rInv);
        //curve.Validate(Q);

        //return Q;
        return Q;
    }
    static byte[] ToDER(byte[] r, byte[] s)
    {

        List<byte> sequence = [2, (byte)r.Length];
        sequence = sequence.Concat(r).ToList();
        sequence.Add(2);
        sequence.Add((byte)s.Length);
        sequence = sequence.Concat(s).ToList();
        sequence.InsertRange(0, new List<byte> {48, (byte)sequence.Count()});
        // Создаем последовательность байтов
        return sequence.ToArray();
    }
    private static Signature FromStringOrThrow(string signature)
    {
        Match match = Regex.Match(signature, @"^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$");
        if (match == null && match.Length == 3)
        {
            throw new Exception("Expecting signature like: SIG_K1_base58signature..");
        }
        if ((!match.Groups[1].Success) && (!match.Groups[2].Success))
        {
            throw new Exception("Expecting signature like: SIG_K1_base58signature..");
        }
        if (match.Groups[1].Value != "K1")
        {
            throw new Exception("K1 signature expected");
        }
        return FromBuffer(KeyUtils.CheckDecode(match.Groups[2].Value, match.Groups[1].Value));
    }

    public static Signature FromBuffer(byte[] buf)
    {
        if (buf == null || buf.Length != 65)
            throw new ArgumentException("Invalid signature length", nameof(buf));

        int i = buf[0];
        if ((i - 27 & 7) != (i - 27))
            throw new ArgumentException("Invalid signature parameter");

        byte[] rBytes = new byte[32];
        Array.Copy(buf, 1, rBytes, 0, 32);
        System.Numerics.BigInteger r = new System.Numerics.BigInteger(rBytes, isUnsigned: true, isBigEndian: true);
        
        byte[] sBytes = new byte[32];
        Array.Copy(buf, 33, sBytes, 0, 32);
        System.Numerics.BigInteger s = new System.Numerics.BigInteger(sBytes, isUnsigned: true, isBigEndian: true);

        return new Signature(r, s, i, buf);
    }
}
