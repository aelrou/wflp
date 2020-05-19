using System;
using System.IO;
using System.Text.RegularExpressions;

namespace wflp.methods
{
    public class WorkDir
    {
        public static bool Find(string[] args)
        {
            if (args == null | args.Length < 1) {
                Console.WriteLine(@"Usage: wflp.exe ""C:\Working\Directory""");
                Console.WriteLine(@"Please specify the working directory for configuration file.");
                return false;
            }

            if (args.Length != 1) {
                Console.WriteLine(@"Only 1 parameter allowed. Found " + args.Length);
                return false;
            }

            Regex pathRegex = new Regex(@"^[a-zA-Z]:\\[^<>:""\/|?*]*$");
            MatchCollection matchedPath = pathRegex.Matches(args[0]);
            if (matchedPath.Count < 1) {
                Console.WriteLine(@"Invalid working directory " + args[0]);
                return false;
            }

            bool first = true;
            while (true) {
                if (Directory.Exists(args[0])) {
                    break;
                }
                else {
                    if (first) {
                        Console.WriteLine(@"Cannot find working directory. Creating...");
                        Directory.CreateDirectory(args[0]);
                        first = false;
                    }
                    else {
                        Console.WriteLine(@"Unable to create " + args[0]);
                        return false;
                    }
                }
            }
            Console.WriteLine(@"Working directory is " + args[0]);
            return true;
        }
    }
}
