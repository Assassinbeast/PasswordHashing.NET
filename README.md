# PasswordHashing.NET
Hash passwords (with salting) easily with this library in dotnet core.

```csharp
string hashedPassword = PasswordHasher.Hash("hello123"); //7407630E05834...
PasswordHasher.Validate("hello123", hashedPassword); //true

string hashedPassword2 = PasswordHasher.Hash("hello123"); //1F751907AC51...
PasswordHasher.Validate("hello123", hashedPassword2); //true

bool isSame = hashedPassword == hashedPassword2; //false
```

* It supports 6 different hashing algorithms:
    * MD5, SHA1, SHA256, SHA384, SHA512 and Blake2b
* `PasswordHasher` is the static class that hashes passwords.
    * You can configure the default settings to use one of those supported hashing algorithms and the length of the salt
    * Default hash algorithm is `Blake2b`
    * Default salt length is `16`
* The produced hashed password are string encoded in hexadecimal
* You can also use an instance `PasswordHasherInstance` instead of the static class `PasswordHasher`
    * It works exactly the same like the static class `PasswordHasher`
* You can use all unicode characters
* Validating passwords with different salt size in the configuration is possible
* The produced hashed passwords are always the same length and can be calculated
    * For example, `SHA256` will always produce a byte array of `32` in length
    * And then the byte array will be turned into a string in hexadecimal format
        * Hexadecimal will always turn each byte into a string of `2` in length
    * This means our hashed password will become `64` in length (exclusive salt)
    * So if you configured the salt to be `16` in length, then the final length of hashed password is `80`


### Set default settings on static class
```csharp
PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA384, 20); //Use SHA384 and Salt size of 20
```

### Use instance object to hash passwords
```csharp
//Use Blake2b algorithm with saltsize of 20
var passwordHasher = PasswordHasherInstance.Create(HashAlgorithm.Blake2b, 20); 
string hashedPassword = passwordHasher.Hash("hello123"); //AED9BF19B9D5DEB3A...
bool correctPassword = password.Validate("hello123", hashedPassword) //true
```
### You can use all unicode characters
```csharp
PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b);
string p1 = "💩😁🙉🥶";
string p2 = "▲↝↯⟳⇨⇶";
string p3 = "七丹亮乪些享";

string h1 = PasswordHasher.Hash(p1);
string h2 = PasswordHasher.Hash(p2);
string h3 = PasswordHasher.Hash(p3);

PasswordHasher.Validate(p1, h1); //true
PasswordHasher.Validate(p2, h2); //true
PasswordHasher.Validate(p3, h3); //true
```

### Validating passwords with different salt size in configuration is possible
```csharp
var passwordHasher1 = PasswordHasherInstance.Create(HashAlgorithm.SHA1, 10);
var passwordHasher2 = PasswordHasherInstance.Create(HashAlgorithm.SHA1, 20);

string hashedPassword = passwordHasher1.Hash("hello123");
passwordHasher2.Validate("hello123", hashedPassword); //true

PasswordHasher.SetDefaultSettings(HashAlgorithm.SHA1, 30); //Test with static class
PasswordHasher.Validate("hello123", hashedPassword); //true
```

### Hashed passwords are always in fixed size
```csharp
PasswordHasher.SetDefaultSettings(HashAlgorithm.Blake2b, 16);
var p1 = PasswordHasher.Hash("u6ClyHyGAj%Oft^j5v6L6PvS45p%j!hEMjR9k");
var p2 = PasswordHasher.Hash("*XXGFG#TA1cA4I1Qa");
var p3 = PasswordHasher.Hash("DNG81T!fY!KJ9YYc0k7ZDjCn6JPUquXx8B&DY1kju87Z2PEIhK3ZIZRgbn*&c!o20El");
var p4 = PasswordHasher.Hash("Xg$k*3PO#mv6%F0HOD890Lhpg5tjds5lNT8Q99lXWMSG9lpH5rg*d");
var p5 = PasswordHasher.Hash("Abc");

//We know the length is 144, because Blake2b will always produce bytearray of 64
//Then we turn the bytearray into a hexidecimal string which becomes 128 in length
//Our salt size is 16, so the final length is 144
bool isTrue = p1.Length == 144; //true
isTrue = p2.Length == 144; //true
isTrue = p3.Length == 144; //true
isTrue = p4.Length == 144; //true
isTrue = p5.Length == 144; //true

Console.WriteLine(PasswordHasher.HashedPasswordSize); //144
```