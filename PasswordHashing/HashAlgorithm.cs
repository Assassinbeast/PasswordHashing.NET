namespace PasswordHashing
{
	public enum HashAlgorithm
	{
		/// <summary>
		/// 32 Characters (exclusive salt)
		/// </summary>
		MD5 = 0,
		/// <summary>
		/// 40 Characters (exclusive salt)
		/// </summary>
		SHA1 = 1,
		/// <summary>
		/// 64 Characters (exclusive salt)
		/// </summary>
		SHA256 = 2,
		/// <summary>
		/// 96 Characters (exclusive salt)
		/// </summary>
		SHA384 = 3,
		/// <summary>
		/// 128 Characters (exclusive salt)
		/// </summary>
		SHA512 = 4,
		/// <summary>
		/// 128 Characters (exclusive salt)
		/// </summary>
		Blake2b = 5
	}
}