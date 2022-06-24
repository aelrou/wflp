using System;
using System.Text.RegularExpressions;

namespace wflp.Methods {
    public class Permission {
        public static bool Elevated() {
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.FileName = @"cmd.exe";
            startInfo.Arguments = @"/C netsh advfirewall set allprofiles state";
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo = startInfo;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            process.Close();

            Regex nonElevatedRegex = new Regex(@".*The requested operation requires elevation \(Run as administrator\)\..*", RegexOptions.IgnoreCase);
            MatchCollection matchedNonElevated = nonElevatedRegex.Matches(output);
            if (matchedNonElevated.Count < 1) {
                Regex elevatedRegex = new Regex(@".*Usage:  set allprofiles \(parameter\) \(value\).*", RegexOptions.IgnoreCase);
                MatchCollection matchedElevated = elevatedRegex.Matches(output);
                if (matchedElevated.Count > 0) {
                    Console.WriteLine(@"Elevated permission detected.");
                    return true;
                }
            }
            Console.WriteLine(@"Unable to run without elevated permission.");
            return false;            
        }
    }
}
