using System;
using CryptographyTool;

public class Demo
{
    public static void Main()
    {
        Cryptography crypt = new Cryptography(
                key: "8$Pklqt?#zoIVwvq-c&S5kEoPj6qnbJR",
                iv: "nChIlDVY!VsjHMLK"
            );

        string content = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas velit nisl, euismod nec dolor ut.";
        string encrypted = crypt.Encrypt(content);
        string decrypted = crypt.Decrypt(encrypted);

        Console.WriteLine(
            "\n\n\n" +
            "Data: {0}\n\n" +
            "Encrypted: {1}\n\n" +
            "Decrypted: {2}\n\n",
            content, encrypted, decrypted
            );
    }
}









