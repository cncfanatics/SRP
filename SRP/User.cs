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
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace SRP
{
    public class User
    {
        /// <summary>
        /// Username to authenticate
        /// </summary>
        public string username { get; protected set; }

        /// <summary>
        /// Password to authenticate
        /// </summary>
        public string password { get; protected set; }

        /// <summary>
        /// True if the user is authenticated, false otherwise
        /// </summary>
        public bool authenticated { get; protected set; }

        public byte[] SessionKey { get { return byte_K; } }

        /// <summary>
        /// N in the SRP formula
        /// </summary>
        private BigInteger N;

        /// <summary>
        /// g in the SRP formula
        /// </summary>
        private BigInteger g;

        /// <summary>
        /// a in the SRP formula
        /// </summary>
        private BigInteger a;

        /// <summary>
        /// A in the SRP formula
        /// </summary>
        private byte[] byte_A;

        /// <summary>
        /// k in the SRP formula
        /// </summary>
        private BigInteger k;

        /// <summary>
        /// H_AMK in the SRP formula
        /// </summary>
        private byte[] H_AMK;

        /// <summary>
        /// Shared session key
        /// </summary>
        byte[] byte_K;

        /// <summary>
        /// Constructor without default values for .NET 2.0 support
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public User(string username, string password) : this(username, password, null, null) {}

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="username">The username to authenticate</param>
        /// <param name="password">The password to authenticate</param>
        /// <param name="byte_N">N as per the SRP formula, if not passed, a default 8096 bit N is used</param>
        /// <param name="byte_g">The corresponding generator value for N, by default, this is decimal 19</param>
        public User(string username, string password, byte[] byte_N, byte[] byte_g)
        {
            // Set stuff
            this.username = username;
            this.password = password;
            this.authenticated = false;
            N = byte_N != null ? new BigInteger(byte_N) : Constants.N;
            g = byte_g != null ? new BigInteger(byte_g) : Constants.g;

            // Generate a random 32 byte a
            byte[] byte_a = new byte[32];
            RNGCryptoServiceProvider.Create().GetBytes(byte_a);
            this.a = new BigInteger(byte_a).abs();

            // Compute A
            byte_A = g.modPow(a, N).getBytes();
            
            // Compute k in byte array form
            byte[] byte_k;
            using (SHA512 h = SHA512.Create())
            {
                byte_k = h.ComputeHash(N.getBytes().Concat(g.getBytes()).ToArray());
            }

            // Get BigInteger k and store it
            this.k = new BigInteger(byte_k).abs();
        }

        /// <summary>
        /// Returns A, which is needed to start authentication.
        /// This should be sent to the verifier along with the username
        /// </summary>
        /// <returns></returns>
        public byte[] StartAuthentication()
        {
            return byte_A;
        }

        /// <summary>
        /// Returns M if the challenge was successfully processed
        /// Otherwise, null is returned
        /// </summary>
        /// <returns>M or null</returns>
        public byte[] ProcessChallenge(byte[] byte_s, byte[] byte_B)
        {
            BigInteger s = new BigInteger(byte_s).abs();
            BigInteger B = new BigInteger(byte_B).abs();

            // SRP-6a dictated safety check
            if(B % N == 0)
            {
                return null;
            }

            // Compute M
            byte[] byte_M;

            using(SHA512 h = SHA512.Create())
            {
                byte[] byte_u = h.ComputeHash(byte_A.Concat(B.getBytes()).ToArray());
            
                BigInteger u = new BigInteger(byte_u);

                // SRP-6a dictated safety check
                if(u == 0)
                {
                    return null;
                }

                // Compute x
                Encoding encoding = new ASCIIEncoding();
                byte[] byte_I = encoding.GetBytes(username);
                byte[] byte_p = encoding.GetBytes(password);
                byte[] byte_x = Common.GenerateX(byte_s, byte_I, byte_p);
                BigInteger x = new BigInteger(byte_x).abs();

                // Compute v
                BigInteger v = g.modPow(x, N).abs();

                // Compute S
                // The remainder is computed here, not the modulo.
                // This means that, if n is negative, we need to do N - remainder to get the modulo
                BigInteger S = (B - k * v).modPow(a + u * x, N);

                if (S < 0)
                {
                    S = N + S;
                }

                // Compute K
                byte_K = h.ComputeHash(S.getBytes());

                // Compute M
                byte_M = Common.GenerateM(N.getBytes(), g.getBytes(), byte_I, byte_s, byte_A, B.getBytes(), byte_K);

                // And finally, hash A, M and K together
                H_AMK = h.ComputeHash(byte_A.Concat(byte_M).Concat(byte_K).ToArray());
            }

            return byte_M;
        }

        /// <summary>
        /// Verify the passed server session
        /// </summary>
        /// <param name="host_H_AMK">The host's H_AMK</param>
        public void VerifySession(byte[] host_H_AMK)
        {
            if(host_H_AMK.Length != H_AMK.Length)
            {
                return;
            }

            for(int i = 0; i < H_AMK.Length; i++)
            {
                if (H_AMK[i] != host_H_AMK[i])
                {
                    return;
                }
            }

            authenticated = true;
        }
    }
}
