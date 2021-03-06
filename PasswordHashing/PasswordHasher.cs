﻿using System;
using System.Collections.Generic;
using System.Data.HashFunction.Blake2;
using System.Security.Cryptography;
using System.Text;

namespace PasswordHashing
{
	public class PasswordHasher
	{
		const int _minSaltSize = 1;
		const int _maxSaltSize = 100;
		internal static readonly UnicodeEncoding Encoder;
		static readonly List<char> _saltChars = new List<char>();
		static Random _rand = new Random();

		static readonly Dictionary<HashAlgorithm, BaseHashAlgorithmItem> _algorithmItems;
		internal static BaseHashAlgorithmItem GetHashAlgorithmItem(HashAlgorithm hashAlgorithm)
		{
			if (_algorithmItems.ContainsKey(hashAlgorithm) == false)
			{
				switch (hashAlgorithm)
				{
					case HashAlgorithm.MD5:
						_algorithmItems.Add(HashAlgorithm.MD5, new MD5Item());
						break;
					case HashAlgorithm.SHA1:
						_algorithmItems.Add(HashAlgorithm.SHA1, new SHA1Item());
						break;
					case HashAlgorithm.SHA256:
						_algorithmItems.Add(HashAlgorithm.SHA256, new SHA256Item());
						break;
					case HashAlgorithm.SHA384:
						_algorithmItems.Add(HashAlgorithm.SHA384, new SHA384Item());
						break;
					case HashAlgorithm.SHA512:
						_algorithmItems.Add(HashAlgorithm.SHA512, new SHA512Item());
						break;
					case HashAlgorithm.Blake2b:
						_algorithmItems.Add(HashAlgorithm.Blake2b, new Blake2BItem());
						break;
					default:
						throw new ArgumentException("No or HashAlgorithm enum");
				}
			}
			return _algorithmItems[hashAlgorithm];
		}

		static int _saltSize;
		static BaseHashAlgorithmItem _curAlgorithmItem;
		public static int HashedPasswordSize => _curAlgorithmItem.Size + _saltSize;

		static PasswordHasher()
		{
			Encoder = new UnicodeEncoding();
			_algorithmItems = new Dictionary<HashAlgorithm, BaseHashAlgorithmItem>();
			for (int i = 48; i <= 57; i++)
				_saltChars.Add((char)i);
			for (int i = 65; i <= 90; i++)
				_saltChars.Add((char)i);
			SetDefaultSettings(HashAlgorithm.SHA256, 16);
		}
		/// <summary>
		/// Hashes a password and returns the hashed password in Hexadecimal string format
		/// </summary>
		public static string Hash(string password)
		{
			return Hash(password, CreateSalt(_saltSize), _curAlgorithmItem);
		}
		internal static string Hash(string pwd, string salt, BaseHashAlgorithmItem algorithmItem)
		{
			string pwdAndSalt = string.Concat(pwd, salt);
			string hashedPwd = algorithmItem.GetHashString(pwdAndSalt);
			string saltAndHashedPwd = string.Concat(hashedPwd, salt);
			return saltAndHashedPwd;
		}

		public static bool Validate(string clearPassword, string hashedPassword)
		{
			return Validate(clearPassword, hashedPassword, _curAlgorithmItem);
		}
		internal static bool Validate(string clearPassword, string hashedPassword, BaseHashAlgorithmItem algorithmItem)
		{
			var salt = hashedPassword.Substring(algorithmItem.Size);
			var hashedPassword2 = Hash(clearPassword, salt, algorithmItem);
			return hashedPassword2 == hashedPassword;
		}

		internal static string CreateSalt(int saltSize)
		{
			StringBuilder sb = new StringBuilder(saltSize);
			for (int i = 0; i < saltSize; i++)
			{
				var saltChar = _saltChars[_rand.Next(0, _saltChars.Count)];
				sb.Append(saltChar);
			}

			return sb.ToString().ToUpper();
		}

		/// <summary>
		/// Default HashAlgorithm is SHA256 and default SaltSize is 16
		/// </summary>
		/// <param name="hashAlgorithm">Choose the hash algorithm to use</param>
		/// <param name="saltSize">Set a salt size from 1 to 100</param>
		public static void SetDefaultSettings(HashAlgorithm? hashAlgorithm = null, int? saltSize = null)
		{
			if (saltSize < _minSaltSize || saltSize > _maxSaltSize)
				throw new Exception($"{nameof(saltSize)} must be in the range of {_minSaltSize} and {_maxSaltSize}");

			if (hashAlgorithm.HasValue)
				_curAlgorithmItem = GetHashAlgorithmItem(hashAlgorithm.Value);
			if (saltSize.HasValue)
				_saltSize = saltSize.Value;
		}
	}
}
