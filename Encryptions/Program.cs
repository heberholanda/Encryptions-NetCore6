using Security;

Console.WriteLine("\n\nSettings for example...");
Console.WriteLine();

string secretKey = "E546C8DF278CD5931069B522E695D4F2";
string plainText = "123456";

Console.WriteLine("   SecretKey: " + secretKey);
Console.WriteLine("   PlainText: " + plainText);

Console.WriteLine("\n");
Console.WriteLine("------------------------ //  MD5  // ------------------------\n");

string encryptedMD5 = EncriptionsHelper.EncryptMD5(plainText, secretKey);
string decryptedMD5 = EncriptionsHelper.DecryptMD5(encryptedMD5, secretKey);
Console.WriteLine("Encrypted: " + encryptedMD5);
Console.WriteLine("Decrypted: " + decryptedMD5);

Console.WriteLine("\n");
Console.WriteLine("------------------------ //  AES  // ------------------------\n");

string encryptedMD5_Base64 = EncriptionsHelper.EncryptAES(plainText, secretKey);
string decryptedMD5_Base64 = EncriptionsHelper.DecryptAES(encryptedMD5_Base64, secretKey);
Console.WriteLine("Encrypted: " + encryptedMD5_Base64);
Console.WriteLine("Decrypted: " + decryptedMD5_Base64);

Console.WriteLine("\n");
Console.WriteLine("------------------------ // SHA256 // ------------------------\n");

string encryptedResult = EncriptionsHelper.EncryptSHA256(plainText, secretKey);
string decryptedResult = EncriptionsHelper.DecryptSHA256(encryptedResult, secretKey);
Console.WriteLine("Encrypted: " + encryptedResult);
Console.WriteLine("Decrypted: " + decryptedResult);

Console.WriteLine("\n");
Console.WriteLine("Press any key to exit...");
Console.ReadLine();



