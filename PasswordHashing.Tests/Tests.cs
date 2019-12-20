using System;
using Xunit;
[assembly: CollectionBehavior(DisableTestParallelization = true)]
namespace PasswordHashing.Tests
{
	public class Tests
	{
		[Fact]
		public void SimpleTest()
		{
			string password = "hej123";
			string hashedPassword = PasswordHasher.Hash(password);
			Assert.True(PasswordHasher.Validate(password, hashedPassword));
		}
		[Fact]
		public void TestLengths()
		{
			string password = "hej123";

			PasswordHasher.SetDefaultSettings(HashAlgorithm.MD5, 16);
			string hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 32);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA1, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 40);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA256, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 64);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA384, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 96);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA512, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 128);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 128);

			//Test for another length here
			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 50);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 50 == 128);
		}

		[Fact]
		public void ValidateMultipleSamePasswords()
		{
			string password = "hej123";

			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 50);
			string hashedP1 = PasswordHasher.Hash(password);
			string hashedP2 = PasswordHasher.Hash(password);

			Assert.True(PasswordHasher.Validate(password, hashedP1));
			Assert.True(PasswordHasher.Validate(password, hashedP2));
			Assert.True(hashedP1 != hashedP2);
			Assert.NotEqual(hashedP1, hashedP2);
		}

		[Fact]
		public void ValidateMultipleWithDifferentSaltSize()
		{
			string password = "hej123";

			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 20);
			string hashedP1 = PasswordHasher.Hash(password);
			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 10);
			string hashedP2 = PasswordHasher.Hash(password);

			Assert.True(PasswordHasher.Validate(password, hashedP1));
			Assert.True(PasswordHasher.Validate(password, hashedP2));
			Assert.True(hashedP1.Length - 20 == 128);
			Assert.True(hashedP2.Length - 10 == 128);
		}

		[Fact]
		public void ValidateWithInstanceAgainstStatic()
		{
			string password = "hej123";

			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 20);
			var passwordHasher = PasswordHasherInstance.Create(HashAlgorithm.Blake2b, 20);

			string hashedP1 = PasswordHasher.Hash(password);
			string hashedP2 = passwordHasher.Hash(password);

			Assert.True(PasswordHasher.Validate(password, hashedP1));
			Assert.True(PasswordHasher.Validate(password, hashedP2));
			Assert.True(passwordHasher.Validate(password, hashedP1));
			Assert.True(passwordHasher.Validate(password, hashedP2));
			Assert.True(hashedP1 != hashedP2);
			Assert.True(hashedP1.Length == hashedP2.Length);
		}

		[Fact]
		public void ValidateWithInstanceAgainstStaticWithDifferentSaltSize()
		{
			string password = "hej123";

			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 20);
			var passwordHasher = PasswordHasherInstance.Create(HashAlgorithm.Blake2b, 10);

			string hashedP1 = PasswordHasher.Hash(password);
			string hashedP2 = passwordHasher.Hash(password);

			Assert.True(PasswordHasher.Validate(password, hashedP1));
			Assert.True(PasswordHasher.Validate(password, hashedP2));
			Assert.True(passwordHasher.Validate(password, hashedP1));
			Assert.True(passwordHasher.Validate(password, hashedP2));
			Assert.True(hashedP1 != hashedP2);
			Assert.True(hashedP1.Length != hashedP2.Length);
			Assert.True(hashedP1.Length - 10 == hashedP2.Length);
		}

		[Fact]
		public void ValidateWithInstances()
		{
			string password = "hej123";

			var passwordHasher1 = PasswordHasherInstance.Create(HashAlgorithm.Blake2b, 10);
			var passwordHasher2 = PasswordHasherInstance.Create(HashAlgorithm.Blake2b, 20);

			string hashedP1 = passwordHasher1.Hash(password);
			string hashedP2 = passwordHasher2.Hash(password);

			Assert.True(passwordHasher1.Validate(password, hashedP1));
			Assert.True(passwordHasher1.Validate(password, hashedP2));
			Assert.True(passwordHasher2.Validate(password, hashedP1));
			Assert.True(passwordHasher2.Validate(password, hashedP2));
		}
	}
}
