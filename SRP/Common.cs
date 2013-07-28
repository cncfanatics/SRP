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

using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace SRP
{
    /// <summary>
    /// Class that contains algorithms that are used several times across different parts of the code
    /// </summary>
    internal static class Common
    {
        /// <summary>
        /// Generate the X value as dictated by the SRP spec
        /// </summary>
        /// <param name="byte_s">The salt</param>
        /// <param name="byte_I">the username</param>
        /// <param name="byte_p">the password</param>
        public static byte[] GenerateX(byte[] byte_s, byte[] byte_I, byte[] byte_p)
        {
            byte[] byte_x;

            using(SHA512 h = SHA512.Create())
            {
                // Concat username and pw
                byte[] userPwHash = h.ComputeHash(byte_I.Concat(Constants.Seperator).Concat(byte_p).ToArray());

                // Hash along the salt and then the hashed username + pw
                byte_x = h.ComputeHash(byte_s.Concat(userPwHash).ToArray());
            }

            return byte_x;
        }

        /// <summary>
        /// Generate the M value as per the SRP spec
        /// </summary>
        /// <param name="byte_N">Large prime number</param>
        /// <param name="byte_g">Generator number</param>
        /// <param name="byte_I">Username</param>
        /// <param name="byte_s">salt</param>
        /// <param name="byte_A">A as per the SRP spec</param>
        /// <param name="byte_B">B as per the SRP spec</param>
        /// <param name="byte_K">K as per the SRP spec</param>
        /// <returns></returns>
        public static byte[] GenerateM(byte[] byte_N, byte[] byte_g, byte[] byte_I, byte[] byte_s, byte[] byte_A, byte[] byte_B, byte[] byte_K)
        {
            byte[] byte_M;

            using (SHA512 h = SHA512.Create())
            {
                byte[] byte_Nxorh = HashXor(byte_N, byte_g);
                byte[] byte_Ih = h.ComputeHash(byte_I);
                byte_M = h.ComputeHash(byte_Nxorh.Concat(byte_Ih).Concat(byte_s).Concat(byte_A).Concat(byte_B).Concat(byte_K).ToArray());
            }

            return byte_M;
        }

        /// <summary>
        /// Hash and xor the passed byte arrays
        /// </summary>
        /// <param name="?"></param>
        /// <returns></returns>
        public static byte[] HashXor(byte[] byte_1, byte[] byte_2)
        {
            byte[] ret;

            using(SHA512 h = SHA512.Create())
            {
                // Hash both byte arrays
                byte_1 = h.ComputeHash(byte_1);
                byte_2 = h.ComputeHash(byte_2);

                // Xor them together
                ret = new byte[byte_1.Length];
                for (int i = 0; i < byte_1.Length; i++)
                {
                    ret[i] = (byte) (byte_1[i] ^ byte_2[i]);
                }
            }

            return ret;
        }
    }
}
