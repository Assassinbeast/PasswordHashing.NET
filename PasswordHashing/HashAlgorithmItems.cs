using System.Data.HashFunction.Blake2;
using System.Security.Cryptography;
using System.Text;

namespace PasswordHashing
{
	abstract class BaseHashAlgorithmItem
	{
		public abstract string GetHashString(string password);
		public int Size { get; protected set; }
	}

	class MD5Item : BaseHashAlgorithmItem
	{
		readonly MD5 md5;
		public MD5Item()
		{
			this.md5 = new MD5CryptoServiceProvider();
			this.Size = this.md5.ComputeHash(new byte[] { 1 }).Length * 2;
		}
		public override string GetHashString(string password)
		{
			var bytes = PasswordHasher.Encoder.GetBytes(password);
			var hashBytes = md5.ComputeHash(bytes);
			StringBuilder sb = new StringBuilder(hashBytes.Length * 2);
			foreach (byte b in hashBytes)
				sb.Append(b.ToString("X2"));
			return sb.ToString();
		}
	}
	class SHA1Item : BaseHashAlgorithmItem
	{
		readonly SHA1 sha1;
		public SHA1Item()
		{
			this.sha1 = new SHA1CryptoServiceProvider();
			this.Size = this.sha1.ComputeHash(new byte[] { 1 }).Length * 2;
		}
		public override string GetHashString(string password)
		{
			var bytes = PasswordHasher.Encoder.GetBytes(password);
			var hashBytes = sha1.ComputeHash(bytes);
			StringBuilder sb = new StringBuilder(hashBytes.Length * 2);
			foreach (byte b in hashBytes)
				sb.Append(b.ToString("X2"));
			return sb.ToString();
		}
	}
	class SHA256Item : BaseHashAlgorithmItem
	{
		readonly SHA256 sha256;
		public SHA256Item()
		{
			this.sha256 = new SHA256CryptoServiceProvider();
			this.Size = this.sha256.ComputeHash(new byte[] { 1 }).Length * 2;
		}
		public override string GetHashString(string password)
		{
			var bytes = PasswordHasher.Encoder.GetBytes(password);
			var hashBytes = sha256.ComputeHash(bytes);
			StringBuilder sb = new StringBuilder(hashBytes.Length * 2);
			foreach (byte b in hashBytes)
				sb.Append(b.ToString("X2"));
			return sb.ToString();
		}
	}
	class SHA384Item : BaseHashAlgorithmItem
	{
		readonly SHA384 sha384;
		public SHA384Item()
		{
			this.sha384 = new SHA384CryptoServiceProvider();
			this.Size = this.sha384.ComputeHash(new byte[] { 1 }).Length * 2;
		}
		public override string GetHashString(string password)
		{
			var bytes = PasswordHasher.Encoder.GetBytes(password);
			var hashBytes = sha384.ComputeHash(bytes);
			StringBuilder sb = new StringBuilder(hashBytes.Length * 2);
			foreach (byte b in hashBytes)
				sb.Append(b.ToString("X2"));
			return sb.ToString();
		}
	}
	class SHA512Item : BaseHashAlgorithmItem
	{
		readonly SHA512 sha512;
		public SHA512Item()
		{
			this.sha512 = new SHA512CryptoServiceProvider();
			this.Size = this.sha512.ComputeHash(new byte[] { 1 }).Length * 2;
		}
		public override string GetHashString(string password)
		{
			var bytes = PasswordHasher.Encoder.GetBytes(password);
			var hashBytes = sha512.ComputeHash(bytes);
			StringBuilder sb = new StringBuilder(hashBytes.Length * 2);
			foreach (byte b in hashBytes)
				sb.Append(b.ToString("X2"));
			return sb.ToString();
		}
	}
	class Blake2BItem : BaseHashAlgorithmItem
	{
		readonly IBlake2B blake2B;
		public Blake2BItem()
		{
			this.blake2B = Blake2BFactory.Instance.Create();
			this.Size = blake2B.ComputeHash(new byte[] { 1 }).Hash.Length * 2;
		}
		public override string GetHashString(string password)
		{
			var bytes = PasswordHasher.Encoder.GetBytes(password);
			var hashBytes = blake2B.ComputeHash(bytes);
			StringBuilder sb = new StringBuilder(hashBytes.Hash.Length * 2);
			foreach (byte b in hashBytes.Hash)
				sb.Append(b.ToString("X2"));
			return sb.ToString();
		}
	}
}