using System.Security.Cryptography;
namespace AngularAuthAPI.Helpers
{
    public static class PasswordHasher
    {
        private static readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static int saltSize = 16;
        private static int hashSize = 20;
        private static int iterations = 10000;
        public static string PasswordHash(string password)
        {
            byte[] salt = new byte[saltSize];
            rng.GetBytes(salt);
            var key =new Rfc2898DeriveBytes(password,salt,iterations,HashAlgorithmName.SHA256);
            var hash = key.GetBytes(hashSize);

            var hashByte=new byte[saltSize+hashSize];
            Array.Copy(salt,0,hashByte,0, saltSize);
            Array.Copy(hash,0,hashByte,saltSize,hashSize);

            var base64Hash=Convert.ToBase64String(hashByte);
            return base64Hash;
        }
        public static bool VerifyPassword(string password,string base64password) 
        {
            var hashBytes=Convert.FromBase64String(base64password);
            var salt=new byte[saltSize];
            Array.Copy(hashBytes,0,salt,0,saltSize);

            var key = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            var hash = key.GetBytes(hashSize);

            for(int i=0;i<hashSize;i++)
            {
                if (hashBytes[i+saltSize] != hash[i])
                    return false;
            }
            return true;
        }
    }
}
