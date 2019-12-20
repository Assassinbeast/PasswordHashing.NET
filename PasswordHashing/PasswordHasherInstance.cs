namespace PasswordHashing
{
	public class PasswordHasherInstance
	{
		readonly BaseHashAlgorithmItem hashAlgorithmItem;
		readonly int saltSize;
		public int HashedPasswordSize => hashAlgorithmItem.Size + saltSize;

		private PasswordHasherInstance(BaseHashAlgorithmItem hashAlgorithmItem, int saltSize)
		{
			this.hashAlgorithmItem = hashAlgorithmItem;
			this.saltSize = saltSize;
		}
		public static PasswordHasherInstance Create(HashAlgorithm hashAlgorithm, int saltSize)
		{
			return new PasswordHasherInstance(PasswordHasher.GetHashAlgorithmItem(hashAlgorithm), saltSize);
		}
		public string Hash(string password)
		{
			return PasswordHasher.Hash(password, PasswordHasher.CreateSalt(this.saltSize), this.hashAlgorithmItem);
		}
		public bool Validate(string clearPassword, string hashedPassword)
		{
			return PasswordHasher.Validate(clearPassword, hashedPassword, this.hashAlgorithmItem);
		}
	}
}