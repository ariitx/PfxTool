using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;

namespace PfxTool
{
    class Program
    {
        static void Main(string[] args)
        {
            var argsLst = args.ToList();
#if DEBUG
            argsLst.Add(@"D:\frp\pfx\20220205_e8c35ea0.pfx");
#endif
            try
            {
                if (argsLst.Count == 1)
                {
                    var fullpath = argsLst[0];
                    if (File.Exists(fullpath))
                    {
                        var filenamewithoutext = System.IO.Path.GetFileNameWithoutExtension(fullpath);
                        var dir = Path.GetDirectoryName(fullpath);
                        using (var cert2 = new X509Certificate2(fullpath, "", X509KeyStorageFlags.Exportable))
                        {
                            //for crt file
                            File.WriteAllText(Path.Combine(dir, filenamewithoutext) + ".crt", ExportToPem(cert2));
                            if (cert2.HasPrivateKey) File.WriteAllText(Path.Combine(dir, filenamewithoutext) + ".key", ExportToKey(cert2));
                            Console.WriteLine("Files exported.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("File not found.");
                    }
                }
                else
                {
                    Console.WriteLine("Pfx file path is required.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

#if DEBUG
            Console.WriteLine("Press anykey to exit.");
            Console.ReadKey();
#endif
        }


        // Define other methods, classes and namespaces here
        // Certificates content has 64 characters per lines
        private const int MaxCharactersPerLine = 64;
        public static string ExportToPem(X509Certificate2 cert)
        {
            var builder = new StringBuilder();
            var certContentBase64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            // Calculates the max number of lines this certificate will take.
            var certMaxNbrLines = Math.Ceiling((double)certContentBase64.Length / MaxCharactersPerLine);

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            for (var index = 0; index < certMaxNbrLines; index++)
            {
                var maxSubstringLength = index * MaxCharactersPerLine + MaxCharactersPerLine > certContentBase64.Length
                    ? certContentBase64.Length - index * MaxCharactersPerLine
                    : MaxCharactersPerLine;
                builder.AppendLine(certContentBase64.Substring(index * MaxCharactersPerLine, maxSubstringLength));
            }
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }
        public static string ExportToKey(X509Certificate2 cert)
        {
            if (!cert.HasPrivateKey) return "";

            var builder = new StringBuilder();
            //var certContentBase64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            var certContentBase64 = Convert.ToBase64String(cert.GetRSAPrivateKey().ExportRSAPrivateKey());
            // Calculates the max number of lines this certificate will take.
            var certMaxNbrLines = Math.Ceiling((double)certContentBase64.Length / MaxCharactersPerLine);

            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            for (var index = 0; index < certMaxNbrLines; index++)
            {
                var maxSubstringLength = index * MaxCharactersPerLine + MaxCharactersPerLine > certContentBase64.Length
                    ? certContentBase64.Length - index * MaxCharactersPerLine
                    : MaxCharactersPerLine;
                builder.AppendLine(certContentBase64.Substring(index * MaxCharactersPerLine, maxSubstringLength));
            }
            builder.AppendLine("-----END PRIVATE KEY-----");

            return builder.ToString();
        }
    }
}
