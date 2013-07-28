/*  This file is part of NETSRP.
 *
 *  NETSRP is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  NETSRP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace SRP
{
    class Verifier
    {
        /// <summary>
        /// The username to verify
        /// </summary>
        public string username { get; protected set; }

        /// <summary>
        /// Whether the user is authenticated
        /// </summary>
        public bool authenticated { get; protected set; }

        /// <summary>
        /// Returns a SessionKey after the user is authenticated that can be used for encrypted communication
        /// </summary>
        public byte[] SessionKey { get { return byte_K; } }

        protected bool safety_failed = false;
        protected byte[] byte_M;
        protected byte[] byte_H_AMK;
        protected byte[] byte_K;

        /// <summary>
        /// Constructor without optional arguments for .NET 2.0 compat
        /// </summary>
        /// <param name="username">username</param>
        /// <param name="byte_s">salt byte array</param>
        /// <param name="byte_v">v byte array (as per SRP spec)</param>
        /// <param name="byte_A">A byte array (as per SRP spec)</param>
        public Verifier(string username, byte[] byte_s, byte[] byte_v, byte[] byte_A) : this(username, byte_s, byte_v, byte_A, null, null)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="username">username</param>
        /// <param name="byte_s">salt byte array</param>
        /// <param name="byte_v">v byte array (as per SRP spec)</param>
        /// <param name="byte_A">A byte array (as per SRP spec)</param>
        /// <param name="byte_N">N byte array, defaulted if not passed</param>
        /// <param name="byte_g">g byte array, defaulted if not passed</param>
        public Verifier(string username, byte[] byte_s, byte[] byte_v, byte[] byte_A, byte[] byte_N, byte[] byte_g)
        {
            // Set stuff
            this.username = username;
            this.authenticated = false;

            // Compute
            using (SHA512 h = SHA512.Create())
            {
                // Get bigIntegers from passed byte arrays
                BigInteger N = byte_N != null ? new BigInteger(byte_N) : Constants.N;
                BigInteger g = byte_g != null ? new BigInteger(byte_g) : Constants.g;
                BigInteger A = new BigInteger(byte_A);
                BigInteger v = new BigInteger(byte_v);
                
                // Compute k
                byte[] byte_k = h.ComputeHash(N.getBytes().Concat(g.getBytes()).ToArray());
                BigInteger k = new BigInteger(byte_k);

                // SRP 6-a dictated check
                safety_failed = A % N == 0;
                if(!safety_failed)
                {
                    // Compute a random cryptographically strong value for b
                    byte[] byte_b = new byte[32];
                    RNGCryptoServiceProvider.Create().GetBytes(byte_b);
                    BigInteger b = new BigInteger(byte_b);

                    // Compute B as per the SRP spec
                    BigInteger B = (k * v + g.modPow(b, N)) % N;

                    // Compute u
                    byte[] byte_u = h.ComputeHash(byte_A.Concat(B.getBytes()).ToArray());
                    BigInteger u = new BigInteger(byte_u);

                    // Compute S as per SRP spec
                    BigInteger S = (A * v.modPow(u, N)).modPow(b, N);

                    // Get the byte array for K, the hashed up S
                    byte_K = h.ComputeHash(S.getBytes());

                    // Compute M now we have all our data
                    byte_M = Common.GenerateM(N.getBytes(), g.getBytes(), new ASCIIEncoding().GetBytes(username), byte_s, byte_A, B.getBytes(), byte_K);

                    // Hash up A M and K now to get H_AMK
                    byte_H_AMK = h.ComputeHash(byte_A.Concat(byte_M).Concat(byte_K).ToArray());
                }
            }
        }

        /// <summary>
        /// Verify the passed session and return the H_AMK on success, which then needs to be sent to the client as confirmation
        /// </summary>
        /// <param name="user_M">The M received from the user</param>
        /// <returns></returns>
        public byte[] VerifySession(byte[] user_M)
        {
            if (!safety_failed && user_M == byte_M)
            {
                authenticated = true;
                return byte_H_AMK;
            }
            else
            {
                return null;
            }
        }
    }
}
