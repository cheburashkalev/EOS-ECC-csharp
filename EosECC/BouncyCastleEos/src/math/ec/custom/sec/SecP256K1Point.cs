using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math.Raw;
using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP256K1Point
        : AbstractFpPoint
    {
        /**
         * Create a point which encodes with point compression.
         * 
         * @param curve
         *            the curve to use
         * @param x
         *            affine x co-ordinate
         * @param y
         *            affine y co-ordinate
         * 
         * @deprecated Use ECCurve.createPoint to construct points
         */
        public SecP256K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : this(curve, x, y, false)
        {
        }

        /**
         * Create a point that encodes with or without point compresion.
         * 
         * @param curve
         *            the curve to use
         * @param x
         *            affine x co-ordinate
         * @param y
         *            affine y co-ordinate
         * @param withCompression
         *            if true encode with point compression
         * 
         * @deprecated per-point compression property will be removed, refer
         *             {@link #getEncoded(bool)}
         */
        public SecP256K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression)
            : base(curve, x, y, withCompression)
        {
            if ((x == null) != (y == null))
                throw new ArgumentException("Exactly one of the field elements is null");
        }

        internal SecP256K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs,
            bool withCompression)
            : base(curve, x, y, zs, withCompression)
        {
        }
        SecP256K1FieldElement Z => GetZCoord(0) == null ? new SecP256K1FieldElement(BigInteger.One) : new SecP256K1FieldElement(GetZCoord(0).ToBigInteger());
        public override bool IsInfinityEOS => this.IsInfinity ? true : (Z.ToBigInteger().SignValue == 0 && YCoord.ToBigInteger().SignValue != 0);

        public override bool IsOnCurveEOS
        {
            get
            {
                if (IsInfinityEOS)
                    return true;
                //Q.affineX
                var p = Curve.Field.Characteristic;
                var zInv = Z.ToBigInteger().ModInverse(p);
                var x = XCoord.ToBigInteger().Multiply(zInv).Mod(p);
                var y = YCoord.ToBigInteger().Multiply(zInv).Mod(p);
                var a = Curve.A.ToBigInteger();
                var b = Curve.B.ToBigInteger();
                

                if (x.SignValue < 0 || x.CompareTo(p) >= 0)
                    return false;
                if (y.SignValue < 0 || y.CompareTo(p) >= 0)
                    return false;
                var lhs = y.Square().Mod(p);
                var rhs = x.Pow(3).Add(a.Multiply(x)).Add(b).Mod(p);
                return lhs.ToString().Equals(rhs.ToString());

            }
        }
        public override bool EqualsEOS(ECPoint other)
        {
            if(base.EqualsEOS(other))
                return true;
            if (this.IsInfinityEOS)
                return other.IsInfinityEOS;
            if (other.IsInfinityEOS)
                return this.IsInfinityEOS;
            var p = this.Curve.Field.Characteristic;
            var oy = other.YCoord.ToBigInteger();
            var y = this.YCoord.ToBigInteger();
            var z = Z.ToBigInteger();
            var x = this.XCoord.ToBigInteger();
            var ox = other.XCoord.ToBigInteger();
            var OZ = other.GetZCoord(0);
            var oz = BigInteger.One;
            if (OZ != null)
                oz = OZ.ToBigInteger();
            var u = oy.Multiply(z).Subtract(y.Multiply(oz)).Mod(p);

            if(u.SignValue != 0)
                return false;

            var v = ox.Multiply(z).Subtract(x.Multiply(oz)).Mod(p);

            return v.SignValue == 0;

        }
        public override bool IsValidEOS()
        {
            if(this.IsInfinityEOS)
                return false;
            if (!this.IsOnCurveEOS)
                return false;
            X9ECParameters curveParams = CustomNamedCurves.GetByName("secp256k1");
            var nQ = this.Multiply(curveParams.N);
            if(!nQ.IsInfinityEOS)
                return false;
            return true;
        }
        protected override ECPoint Detach()
        {
            return new SecP256K1Point(null, AffineXCoord, AffineYCoord);
        }
        public override ECPoint MultiplyEOS(BigInteger b)
        {
            if (this.Curve.Infinity == this)
                return this;
            if (b.SignValue == 0)
                return this.Curve.Infinity;
            var e = b;
            var h = e.Multiply(BigInteger.Three);

            var neg = this.Negate();
            ECPoint R = this;

            for (var i = h.BitLength - 2; i > 0; i--)
            {
                var hbit = h.TestBit(i);
                var ebit = e.TestBit(i);

                R = R.TwiceEOS();

                if (hbit != ebit)
                {
                    R = R.AddEOS(hbit ? this : neg);
                }
            }
            return R;
        }
        public override ECPoint Add(ECPoint b)
        {
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return this;
            if (this == b)
                return Twice();

            ECCurve curve = this.Curve;

            SecP256K1FieldElement X1 = (SecP256K1FieldElement)this.RawXCoord, Y1 = (SecP256K1FieldElement)this.RawYCoord;
            SecP256K1FieldElement X2 = (SecP256K1FieldElement)b.RawXCoord, Y2 = (SecP256K1FieldElement)b.RawYCoord;

            SecP256K1FieldElement Z1 = (SecP256K1FieldElement)this.RawZCoords[0];
            SecP256K1FieldElement Z2 = (SecP256K1FieldElement)b.RawZCoords[0];

            uint c;
            uint[] tt1 = Nat256.CreateExt();
            uint[] t2 = Nat256.Create();
            uint[] t3 = Nat256.Create();
            uint[] t4 = Nat256.Create();

            bool Z1IsOne = Z1.IsOne;
            uint[] U2, S2;
            if (Z1IsOne)
            {
                U2 = X2.x;
                S2 = Y2.x;
            }
            else
            {
                S2 = t3;
                SecP256K1Field.Square(Z1.x, S2);

                U2 = t2;
                SecP256K1Field.Multiply(S2, X2.x, U2);

                SecP256K1Field.Multiply(S2, Z1.x, S2);
                SecP256K1Field.Multiply(S2, Y2.x, S2);
            }

            bool Z2IsOne = Z2.IsOne;
            uint[] U1, S1;
            if (Z2IsOne)
            {
                U1 = X1.x;
                S1 = Y1.x;
            }
            else
            {
                S1 = t4;
                SecP256K1Field.Square(Z2.x, S1);

                U1 = tt1;
                SecP256K1Field.Multiply(S1, X1.x, U1);

                SecP256K1Field.Multiply(S1, Z2.x, S1);
                SecP256K1Field.Multiply(S1, Y1.x, S1);
            }

            uint[] H = Nat256.Create();
            SecP256K1Field.Subtract(U1, U2, H);

            uint[] R = t2;
            SecP256K1Field.Subtract(S1, S2, R);

            // Check if b == this or b == -this
            if (Nat256.IsZero(H))
            {
                if (Nat256.IsZero(R))
                {
                    // this == b, i.e. this must be doubled
                    return this.Twice();
                }

                // this == -b, i.e. the result is the point at infinity
                return curve.Infinity;
            }

            uint[] HSquared = t3;
            SecP256K1Field.Square(H, HSquared);

            uint[] G = Nat256.Create();
            SecP256K1Field.Multiply(HSquared, H, G);

            uint[] V = t3;
            SecP256K1Field.Multiply(HSquared, U1, V);

            SecP256K1Field.Negate(G, G);
            Nat256.Mul(S1, G, tt1);

            c = Nat256.AddBothTo(V, V, G);
            SecP256K1Field.Reduce32(c, G);

            SecP256K1FieldElement X3 = new SecP256K1FieldElement(t4);
            SecP256K1Field.Square(R, X3.x);
            SecP256K1Field.Subtract(X3.x, G, X3.x);

            SecP256K1FieldElement Y3 = new SecP256K1FieldElement(G);
            SecP256K1Field.Subtract(V, X3.x, Y3.x);
            SecP256K1Field.MultiplyAddToExt(Y3.x, R, tt1);
            SecP256K1Field.Reduce(tt1, Y3.x);

            SecP256K1FieldElement Z3 = new SecP256K1FieldElement(H);
            if (!Z1IsOne)
            {
                SecP256K1Field.Multiply(Z3.x, Z1.x, Z3.x);
            }
            if (!Z2IsOne)
            {
                SecP256K1Field.Multiply(Z3.x, Z2.x, Z3.x);
            }

            ECFieldElement[] zs = new ECFieldElement[] { Z3 };

            return new SecP256K1Point(curve, X3, Y3, zs, IsCompressed);
        }
        public override ECPoint Twice()
        {
            if (this.IsInfinity)
                return this;

            ECCurve curve = this.Curve;

            SecP256K1FieldElement Y1 = (SecP256K1FieldElement)this.RawYCoord;
            if (Y1.IsZero)
                return curve.Infinity;

            SecP256K1FieldElement X1 = (SecP256K1FieldElement)this.RawXCoord, Z1 = (SecP256K1FieldElement)this.RawZCoords[0];

            uint c;

            uint[] Y1Squared = Nat256.Create();
            SecP256K1Field.Square(Y1.x, Y1Squared);

            uint[] T = Nat256.Create();
            SecP256K1Field.Square(Y1Squared, T);

            uint[] M = Nat256.Create();
            SecP256K1Field.Square(X1.x, M);
            c = Nat256.AddBothTo(M, M, M);
            SecP256K1Field.Reduce32(c, M);

            uint[] S = Y1Squared;
            SecP256K1Field.Multiply(Y1Squared, X1.x, S);
            c = Nat.ShiftUpBits(8, S, 2, 0);
            SecP256K1Field.Reduce32(c, S);

            uint[] t1 = Nat256.Create();
            c = Nat.ShiftUpBits(8, T, 3, 0, t1);
            SecP256K1Field.Reduce32(c, t1);

            SecP256K1FieldElement X3 = new SecP256K1FieldElement(T);
            SecP256K1Field.Square(M, X3.x);
            SecP256K1Field.Subtract(X3.x, S, X3.x);
            SecP256K1Field.Subtract(X3.x, S, X3.x);

            SecP256K1FieldElement Y3 = new SecP256K1FieldElement(S);
            SecP256K1Field.Subtract(S, X3.x, Y3.x);
            SecP256K1Field.Multiply(Y3.x, M, Y3.x);
            SecP256K1Field.Subtract(Y3.x, t1, Y3.x);

            SecP256K1FieldElement Z3 = new SecP256K1FieldElement(M);
            SecP256K1Field.Twice(Y1.x, Z3.x);
            if (!Z1.IsOne)
            {
                SecP256K1Field.Multiply(Z3.x, Z1.x, Z3.x);
            }

            return new SecP256K1Point(curve, X3, Y3, new ECFieldElement[] { Z3 }, IsCompressed);
        }
        public override ECPoint AddEOS(ECPoint B)
        {
            if (this.IsInfinity)
                return B;
            if (B.IsInfinity)
                return B;
            var x1 = this.XCoord.ToBigInteger();
            var y1 = this.YCoord.ToBigInteger();
            var x2 = B.XCoord.ToBigInteger();
            var y2 = B.YCoord.ToBigInteger();
            var p = this.Curve.Field.Characteristic;

            var Z1 = this.GetZCoord(0);
            BigInteger z1;
            if (Z1 != null)
                z1 = Z1.ToBigInteger();
            else
                z1 = BigInteger.One;
            var Z2 = B.GetZCoord(0);
            BigInteger z2;
            if (Z2 != null)
                z2 = Z2.ToBigInteger();
            else
                z2 = BigInteger.One;
            var u = y2.Multiply(z1).Subtract(y1.Multiply(z2)).Mod(p);

            var v = x2.Multiply(z1).Subtract(x1.Multiply(z2)).Mod(p);

            if (v.SignValue == 0)
            {
                if (u.SignValue == 0)
                {
                    return this.TwiceEOS();
                }
                return this.Curve.Infinity;
            }

            var v2 = v.Square();
            var v3 = v2.Multiply(v);
            var x1v2 = x1.Multiply(v2);
            var zu2 = u.Square().Multiply(z1);

            // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
            var x3 = zu2.Subtract(x1v2.ShiftLeft(1)).Multiply(z2).Subtract(v3).Multiply(v).Mod(p);
            // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
            var y3 = x1v2.Multiply(BigInteger.Three).Multiply(u).Subtract(y1.Multiply(v3)).Subtract(zu2.Multiply(u)).Multiply(z2).Add(u.Multiply(v3)).Mod(p);
            // z3 = v^3 * z1 * z2
            var z3 = v3.Multiply(z1).Multiply(z2).Mod(p);
            return new SecP256K1Point(this.Curve, new SecP256K1FieldElement(x3), new SecP256K1FieldElement(y3), new ECFieldElement[] { new SecP256K1FieldElement(z3) }, true);
        }
        public override ECPoint TwiceEOS()
        {
            if (this.IsInfinity)
                return this;

            ECCurve curve = this.Curve;

            BigInteger Y1 = this.RawYCoord.ToBigInteger();
            if (Y1.SignValue == 0)
                return curve.Infinity;

            BigInteger X1 = this.RawXCoord.ToBigInteger();
            var Z1 = this.GetZCoord(0);
            var z1 = BigInteger.One;
            if (Z1 != null)
            {
                z1 = Z1.ToBigInteger();
            }
            uint c;
            var p = curve.Field.Characteristic;
            var y1z1 = Y1.Multiply(z1).Mod(p);
            var y1sqz1 = y1z1.Multiply(Y1).Mod(p);
            var a = curve.A.ToBigInteger();

            // w = 3 * x1^2 + a * z1^2
            var w = X1.Square().Multiply(BigInteger.Three);

            if (a.SignValue != 0)
            {
                w = w.Add(z1.Square().Multiply(a));
            }

            w = w.Mod(p);

            var x3 = w.Square().Subtract(X1.ShiftLeft(3).Multiply(y1sqz1)).ShiftLeft(1).Multiply(y1z1).Mod(p);
            //var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.pow(3)).mod(this.curve.p)
            var y3 = w.Multiply(BigInteger.Three).Multiply(X1).Subtract(y1sqz1.ShiftLeft(1)).ShiftLeft(2).Multiply(y1sqz1).Subtract(w.Pow(3)).Mod(p);

            var z3 = y1z1.Pow(3).ShiftLeft(3).Mod(p);
            //uint[] Y1Squared = Nat256.Create();
            //SecP256K1Field.Square(Y1.x, Y1Squared);
            //
            //uint[] T = Nat256.Create();
            //SecP256K1Field.Square(Y1Squared, T);
            //
            //uint[] M = Nat256.Create();
            //SecP256K1Field.Square(X1.x, M);
            //c = Nat256.AddBothTo(M, M, M);
            //SecP256K1Field.Reduce32(c, M);
            //
            //uint[] S = Y1Squared;
            //SecP256K1Field.Multiply(Y1Squared, X1.x, S);
            //c = Nat.ShiftUpBits(8, S, 2, 0);
            //SecP256K1Field.Reduce32(c, S);
            //
            //uint[] t1 = Nat256.Create();
            //c = Nat.ShiftUpBits(8, T, 3, 0, t1);
            //SecP256K1Field.Reduce32(c, t1);
            //
            //SecP256K1FieldElement X3 = new SecP256K1FieldElement(T);
            //SecP256K1Field.Square(M, X3.x);
            //SecP256K1Field.Subtract(X3.x, S, X3.x);
            //SecP256K1Field.Subtract(X3.x, S, X3.x);
            //
            //SecP256K1FieldElement Y3 = new SecP256K1FieldElement(S);
            //SecP256K1Field.Subtract(S, X3.x, Y3.x);
            //SecP256K1Field.Multiply(Y3.x, M, Y3.x);
            //SecP256K1Field.Subtract(Y3.x, t1, Y3.x);
            //
            //SecP256K1FieldElement Z3 = new SecP256K1FieldElement(M);
            //SecP256K1Field.Twice(Y1.x, Z3.x);
            //if (!Z1.IsOne)
            //{
            //    SecP256K1Field.Multiply(Z3.x, Z1.x, Z3.x);
            //}
            //
            return new SecP256K1Point(curve, new SecP256K1FieldElement(x3), new SecP256K1FieldElement(y3), new ECFieldElement[] { new SecP256K1FieldElement(z3) }, true);
        }

        public override ECPoint TwicePlus(ECPoint b)
        {
            if (this == b)
                return ThreeTimes();
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return Twice();

            ECFieldElement Y1 = this.RawYCoord;
            if (Y1.IsZero)
                return b;

            return Twice().Add(b);
        }

        public override ECPoint ThreeTimes()
        {
            if (this.IsInfinity || this.RawYCoord.IsZero)
                return this;

            // NOTE: Be careful about recursions between TwicePlus and ThreeTimes
            return Twice().Add(this);
        }

        public override ECPoint Negate()
        {
            if (IsInfinity)
                return this;

            return new SecP256K1Point(Curve, RawXCoord, RawYCoord.Negate(), RawZCoords, IsCompressed);
        }
    }
}
