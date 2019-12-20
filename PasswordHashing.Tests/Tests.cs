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
			string password = "hello123";
			string hashedPassword = PasswordHasher.Hash(password);
			Assert.True(PasswordHasher.Validate(password, hashedPassword));
		}
		[Fact]
		public void TestHashedPasswordLengths()
		{
			string password = "hello123";

			PasswordHasher.SetDefaultSettings(HashAlgorithm.MD5, 16);
			string hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 32);
			Assert.True(PasswordHasher.HashedPasswordSize == hashedPassword.Length);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA1, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 40);
			Assert.True(PasswordHasher.HashedPasswordSize == hashedPassword.Length);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA256, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 64);
			Assert.True(PasswordHasher.HashedPasswordSize == hashedPassword.Length);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA384, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 96);
			Assert.True(PasswordHasher.HashedPasswordSize == hashedPassword.Length);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA512, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 128);
			Assert.True(PasswordHasher.HashedPasswordSize == hashedPassword.Length);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 16);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 16 == 128);
			Assert.True(PasswordHasher.HashedPasswordSize == hashedPassword.Length);

			//Test for another length here
			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 50);
			hashedPassword = PasswordHasher.Hash(password);
			Assert.True(hashedPassword.Length - 50 == 128);
			Assert.True(PasswordHasher.HashedPasswordSize == hashedPassword.Length);
		}

		[Fact]
		public void ValidateMultipleSamePasswords()
		{
			string password = "hello123";

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
			string password = "hello123";

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
			string password = "hello123";

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
			string password = "hello123";

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
			string password = "hello123";

			var passwordHasher1 = PasswordHasherInstance.Create(HashAlgorithm.Blake2b, 10);
			var passwordHasher2 = PasswordHasherInstance.Create(HashAlgorithm.Blake2b, 20);

			string hashedP1 = passwordHasher1.Hash(password);
			string hashedP2 = passwordHasher2.Hash(password);

			Assert.True(passwordHasher1.Validate(password, hashedP1));
			Assert.True(passwordHasher1.Validate(password, hashedP2));
			Assert.True(passwordHasher2.Validate(password, hashedP1));
			Assert.True(passwordHasher2.Validate(password, hashedP2));

			Assert.True(passwordHasher1.HashedPasswordSize == hashedP1.Length);
			Assert.True(passwordHasher2.HashedPasswordSize == hashedP2.Length);
		}
		[Fact]
		public void PasswordsAreAlwaysInFixedSize()
		{
			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 16);
			var p1 = PasswordHasher.Hash("u6ClyHyGAj%Oft^j5v6L6PvS45p%j!hEMjR9k");
			var p2 = PasswordHasher.Hash("*XXGFG#TA1cA4I1Qa");
			var p3 = PasswordHasher.Hash("DNG81T!fY!KJ9YYc0k7ZDjCn6JPUquXx8B&DY1kju87Z2PEIhK3ZIZRgbn*&c!o20El");
			var p4 = PasswordHasher.Hash("Xg$k*3PO#mv6%F0HOD890Lhpg5tjds5lNT8Q99lXWMSG9lpH5rg*d");
			var p5 = PasswordHasher.Hash("Abc");

			Assert.True(p1.Length == 144);
			Assert.True(p2.Length == 144);
			Assert.True(p3.Length == 144);
			Assert.True(p4.Length == 144);
			Assert.True(p5.Length == 144);

			Assert.True(PasswordHasher.HashedPasswordSize == 144);
		}
		[Fact]
		public void PasswordsAreAlwaysInFixedSize2()
		{
			var hashAlgorithms = Enum.GetValues(typeof(HashAlgorithm));

			//Test all algorithms
			for (int i = 0; i < hashAlgorithms.Length; i++)
			{
				var hashAlgorithm = (HashAlgorithm)hashAlgorithms.GetValue(i);
				PasswordHasher.SetDefaultSettings(hashAlgorithm, 16);
				var p1 = PasswordHasher.Hash("u6ClyHyGAj%Oft^j5v6L6PvS45p%j!hEMjR9k");
				var p2 = PasswordHasher.Hash("*XXGFG#TA1cA4I1Qa");
				var p3 = PasswordHasher.Hash("DNG81T!fY!KJ9YYc0k7ZDjCn6JPUquXx8B&DY1kju87Z2PEIhK3ZIZRgbn*&c!o20El");
				var p4 = PasswordHasher.Hash("Xg$k*3PO#mv6%F0HOD890Lhpg5tjds5lNT8Q99lXWMSG9lpH5rg*d");
				var p5 = PasswordHasher.Hash("Abc");

				Assert.Equal(p1.Length, p2.Length);
				Assert.Equal(p1.Length, p3.Length);
				Assert.Equal(p1.Length, p4.Length);
				Assert.Equal(p1.Length, p5.Length);
			}

			string pwd = null;
			PasswordHasher.SetDefaultSettings(HashAlgorithm.MD5, 10);
			pwd = PasswordHasher.Hash("hello");
			Assert.Equal(42, pwd.Length);
			Assert.Equal(42, PasswordHasher.HashedPasswordSize);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA1, 10);
			pwd = PasswordHasher.Hash("hello");
			Assert.Equal(50, pwd.Length);
			Assert.Equal(50, PasswordHasher.HashedPasswordSize);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA256, 10);
			pwd = PasswordHasher.Hash("hello");
			Assert.Equal(74, pwd.Length);
			Assert.Equal(74, PasswordHasher.HashedPasswordSize);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA384, 10);
			pwd = PasswordHasher.Hash("hello");
			Assert.Equal(106, pwd.Length);
			Assert.Equal(106, PasswordHasher.HashedPasswordSize);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA512, 10);
			pwd = PasswordHasher.Hash("hello");
			Assert.Equal(138, pwd.Length);
			Assert.Equal(138, PasswordHasher.HashedPasswordSize);

			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 10);
			pwd = PasswordHasher.Hash("hello");
			Assert.Equal(138, pwd.Length);
			Assert.Equal(138, PasswordHasher.HashedPasswordSize);
		}

		[Fact]
		public void AllUnicodeAreAllowed()
		{
			PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b);
			string p1 = "💩😁😂";
			string p2 = "▲↝↯⟳⇨⇶";
			string p3 = "七丹亮乪些享";

			string h1 = PasswordHasher.Hash(p1);
			string h2 = PasswordHasher.Hash(p2);
			string h3 = PasswordHasher.Hash(p3);

			Assert.True(PasswordHasher.Validate(p1, h1));
			Assert.True(PasswordHasher.Validate(p2, h2));
			Assert.True(PasswordHasher.Validate(p3, h3));

			Assert.True(PasswordHasher.HashedPasswordSize == h1.Length);
			Assert.True(PasswordHasher.HashedPasswordSize == h2.Length);
			Assert.True(PasswordHasher.HashedPasswordSize == h3.Length);
		}
	}
}
