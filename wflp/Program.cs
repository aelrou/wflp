using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace wflp {
    class Program {
        const string FormatDateStamp = @"yyyy-MM-ddTHH:mm:ss.fff";

        const string Raw = @"raw";
        const string DateStamp = @"date-time";
        const string Action = @"action";
        const string Protocol = @"protocol";
        const string SrcIp = @"src-ip";
        const string DstIp = @"dst-ip";
        const string SrcPort = @"src-port";
        const string DstPort = @"dst-port";
        const string Size = @"size";
        const string TcpFlags = @"tcpflags";
        const string TcpSyn = @"tcpsyn";
        const string TcpAck = @"tcpack";
        const string TcpWin = @"tcpwin";
        const string IcmpType = @"icmptype";
        const string IcmpCode = @"icmpcode";
        const string Info = @"info";
        const string Path = @"path";

        const string HeaderPattern = @"^#.+";
        const string DataPattern = @"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (ALLOW|DROP) (TCP|UDP|ICMP|2) ([\d\.]{7,15}|[\da-f:]{2,39}) ([\d\.]{7,15}|[\da-f:]{2,39}) ([\d-]{1,5}) ([\d-]{1,5}) ([\d]+) ([S-]) ([\d-]+) ([\d-]+) ([\d-]+) ([\d-]+) ([\d-]+) ([-]) (SEND|RECEIVE)$";

        static void Main(string[] args) {
            DateTime startTime = DateTime.Now;

            if (args == null | args.Length < 1) {
                Console.WriteLine(@"Usage: wflp.exe ""C:\Working\Directory""");
                Console.WriteLine(@"Please specify the working directory for configuration files.");
                Console.ReadKey();
                Environment.Exit(1);
            }
            if (args.Length != 1) {
                Console.WriteLine(@"Only 1 parameter allowed. Found " + args.Length);
                Console.ReadKey();
                Environment.Exit(1);
            }
            string workingDirectory = args[0];
            if (!(Directory.Exists(workingDirectory))) {
                Console.WriteLine(@"Cannot access working directory " + workingDirectory);
                Console.ReadKey();
                Environment.Exit(1);
            }

            EnvVar environmentVariables;
            string jsonEnvironmentFile = workingDirectory + @"\environment.json";
            if (!(File.Exists(jsonEnvironmentFile))) {
                Console.WriteLine(@"Cannot access configuration file " + jsonEnvironmentFile);
                environmentVariables = new EnvVar(true);
                string JSONresult = JsonConvert.SerializeObject(environmentVariables, Formatting.Indented);
                using (var tw = new StreamWriter(jsonEnvironmentFile, false)) {
                    tw.WriteLine(JSONresult.ToString());
                    tw.Close();
                }
                Console.ReadKey();
                Environment.Exit(1);
            }

            using(StreamReader reader = File.OpenText(jsonEnvironmentFile)) {
                JsonSerializer serializer = new JsonSerializer();
                environmentVariables = (EnvVar)serializer.Deserialize(reader, typeof(EnvVar));
            }

            string firewallData = environmentVariables.DataDirectory + @"\" + environmentVariables.DataFile;
            if (!(File.Exists(firewallData))) {
                Console.WriteLine(@"Cannot access firewall data file " + firewallData);
                Console.ReadKey();
                Environment.Exit(1);
            }

            string firewallOldData = environmentVariables.DataDirectory + @"\" + environmentVariables.OldDataFile;
            if (!(File.Exists(firewallOldData))) {
                Console.WriteLine(@"Cannot access firewall old data file " + firewallOldData);
                Console.ReadKey();
                Environment.Exit(1);
            }

            string firewallDataCopy = environmentVariables.DataDirectory + @"\" + environmentVariables.DataFileCopy;
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.FileName = @"cmd.exe";
            startInfo.Arguments = @"/C copy /b """ + firewallData + @""" """ + firewallDataCopy + @"""";
            process.StartInfo = startInfo;
            process.Start();
            Console.WriteLine(process.StandardOutput.ReadToEnd());
            process.WaitForExit();
            process.Close();

            string firewallOldDataCopy = environmentVariables.DataDirectory + @"\" + environmentVariables.OldDataFileCopy;
            System.Diagnostics.Process process2 = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo2 = new System.Diagnostics.ProcessStartInfo();
            startInfo2.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo2.UseShellExecute = false;
            startInfo2.RedirectStandardOutput = true;
            startInfo2.FileName = @"cmd.exe";
            startInfo2.Arguments = @"/C copy /b """ + firewallOldData + @""" """ + firewallOldDataCopy + @"""";
            process2.StartInfo = startInfo2;
            process2.Start();
            Console.WriteLine(process2.StandardOutput.ReadToEnd());
            process2.WaitForExit();
            process2.Close();

            List<string> unhandledLines = new List<string>();

            Regex headerRegex = new Regex(HeaderPattern, RegexOptions.IgnoreCase);
            MatchCollection matchedHeader;

            Regex dataRegex = new Regex(DataPattern, RegexOptions.IgnoreCase);
            MatchCollection matchedData;

            Dictionary<string, string> connection;
            Dictionary<string, Dictionary<string, string>> receivedAllowedConnections = new Dictionary<string, Dictionary<string, string>>();

            int headerCount = 0;
            int logDataCount = 0;

            string[] lines = File.ReadAllLines(firewallDataCopy);
            foreach (string line in lines) {
                matchedHeader = headerRegex.Matches(line);
                if (!(matchedHeader.Count == 0)) {
                    headerCount++;
                }
                else {
                    matchedData = dataRegex.Matches(line);
                    if (!(matchedData.Count == 0)) {
                        logDataCount++;
                        if (matchedData[0].Groups.Count == 18) {
                            connection = new Dictionary<string, string>();
                            connection.Add(Raw, matchedData[0].Groups[0].Value);
                            connection.Add(DateStamp, matchedData[0].Groups[1].Value + @"T" + matchedData[0].Groups[2].Value + @".000");
                            connection.Add(Action, matchedData[0].Groups[3].Value);
                            connection.Add(Protocol, matchedData[0].Groups[4].Value);
                            connection.Add(SrcIp, matchedData[0].Groups[5].Value);
                            connection.Add(DstIp, matchedData[0].Groups[6].Value);
                            connection.Add(SrcPort, matchedData[0].Groups[7].Value);
                            connection.Add(DstPort, matchedData[0].Groups[8].Value);
                            connection.Add(Size, matchedData[0].Groups[9].Value);
                            connection.Add(TcpFlags, matchedData[0].Groups[11].Value);
                            connection.Add(TcpSyn, matchedData[0].Groups[11].Value);
                            connection.Add(TcpAck, matchedData[0].Groups[12].Value);
                            connection.Add(TcpWin, matchedData[0].Groups[13].Value);
                            connection.Add(IcmpType, matchedData[0].Groups[14].Value);
                            connection.Add(IcmpCode, matchedData[0].Groups[15].Value);
                            connection.Add(Info, matchedData[0].Groups[16].Value);
                            connection.Add(Path, matchedData[0].Groups[17].Value);
                            if (connection[Action].Equals(@"ALLOW", StringComparison.OrdinalIgnoreCase)) {
                                if (connection[Path].Equals(@"RECEIVE", StringComparison.OrdinalIgnoreCase)) {
                                    while (true) {
                                        if (receivedAllowedConnections.ContainsKey(connection[DateStamp])) {
                                            DateTime connectionDatetime = DateTime.Parse(connection[DateStamp].ToString()).AddMilliseconds(1);
                                            connection[DateStamp] = connectionDatetime.ToString(FormatDateStamp);
                                        }
                                        else {
                                            receivedAllowedConnections.Add(connection[DateStamp], connection);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            unhandledLines.Add(line);
                        }
                    }
                    else {
                        if (line.Length > 0 ) {
                            unhandledLines.Add(line);
                        }
                    }
                }
            }

            string[] linesOld = File.ReadAllLines(firewallOldDataCopy);
            foreach (string line in linesOld) {
                matchedHeader = headerRegex.Matches(line);
                if (!(matchedHeader.Count == 0)) {
                    headerCount++;
                }
                else {
                    matchedData = dataRegex.Matches(line);
                    if (!(matchedData.Count == 0)) {
                        logDataCount++;
                        if (matchedData[0].Groups.Count == 18) {
                            connection = new Dictionary<string, string>();
                            connection.Add(Raw, matchedData[0].Groups[0].Value);
                            connection.Add(DateStamp, matchedData[0].Groups[1].Value + @"T" + matchedData[0].Groups[2].Value + @".000");
                            connection.Add(Action, matchedData[0].Groups[3].Value);
                            connection.Add(Protocol, matchedData[0].Groups[4].Value);
                            connection.Add(SrcIp, matchedData[0].Groups[5].Value);
                            connection.Add(DstIp, matchedData[0].Groups[6].Value);
                            connection.Add(SrcPort, matchedData[0].Groups[7].Value);
                            connection.Add(DstPort, matchedData[0].Groups[8].Value);
                            connection.Add(Size, matchedData[0].Groups[9].Value);
                            connection.Add(TcpFlags, matchedData[0].Groups[11].Value);
                            connection.Add(TcpSyn, matchedData[0].Groups[11].Value);
                            connection.Add(TcpAck, matchedData[0].Groups[12].Value);
                            connection.Add(TcpWin, matchedData[0].Groups[13].Value);
                            connection.Add(IcmpType, matchedData[0].Groups[14].Value);
                            connection.Add(IcmpCode, matchedData[0].Groups[15].Value);
                            connection.Add(Info, matchedData[0].Groups[16].Value);
                            connection.Add(Path, matchedData[0].Groups[17].Value);
                            if (connection[Action].Equals(@"ALLOW", StringComparison.OrdinalIgnoreCase)) {
                                if (connection[Path].Equals(@"RECEIVE", StringComparison.OrdinalIgnoreCase)) {
                                    while (true) {
                                        if (receivedAllowedConnections.ContainsKey(connection[DateStamp])) {
                                            DateTime connectionDatetime = DateTime.Parse(connection[DateStamp].ToString()).AddMilliseconds(1);
                                            connection[DateStamp] = connectionDatetime.ToString(FormatDateStamp);
                                        }
                                        else {
                                            receivedAllowedConnections.Add(connection[DateStamp], connection);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            unhandledLines.Add(line);
                        }
                    }
                    else {
                        if (line.Length > 0 ) {
                            unhandledLines.Add(line);
                        }
                    }
                }
            }

            File.Delete(firewallDataCopy);
            File.Delete(firewallOldDataCopy);

            Dictionary<string, Dictionary<string, string>> sshConnections = new Dictionary<string, Dictionary<string, string>>();
            Dictionary<string, Dictionary<string, string>> rdpConnections = new Dictionary<string, Dictionary<string, string>>();
            Dictionary<string, Dictionary<string, string>> icmpConnections = new Dictionary<string, Dictionary<string, string>>();

            foreach (var outerPair in receivedAllowedConnections) {
                foreach (var innerPair in outerPair.Value) {
                    if (innerPair.Key.Equals(DstPort, StringComparison.OrdinalIgnoreCase)) {
                        if (innerPair.Value.Equals(@"22", StringComparison.OrdinalIgnoreCase)) {
                            sshConnections.Add(outerPair.Key, outerPair.Value);
                        }
                        if (innerPair.Value.Equals(@"3389", StringComparison.OrdinalIgnoreCase)) {
                            rdpConnections.Add(outerPair.Key, outerPair.Value);
                        }
                    }
                    if (innerPair.Key.Equals(Protocol, StringComparison.OrdinalIgnoreCase)) {
                        if (innerPair.Value.Equals(@"ICMP", StringComparison.OrdinalIgnoreCase)) {
                            icmpConnections.Add(outerPair.Key, outerPair.Value);
                        }
                    }
                }
            }

            foreach (var outerPair in receivedAllowedConnections) {
                string output = null;
                bool first = true;
                foreach (var innerPair in outerPair.Value) {
                    if (!(innerPair.Key.Equals(Raw, StringComparison.OrdinalIgnoreCase))) {
                        if (first) {
                            output = innerPair.Value;
                        }
                        else {
                            output = output + " " + innerPair.Value;
                        }
                        first = false;
                    }
                    //Console.WriteLine(output);
                }
            }

            foreach (var outerPair in sshConnections) {
                string output = null;
                bool first = true;
                foreach (var innerPair in outerPair.Value) {
                    if (!(innerPair.Key.Equals(Raw, StringComparison.OrdinalIgnoreCase))) {
                        if (first) {
                            output = innerPair.Value;
                        }
                        else {
                            output = output + " " + innerPair.Value;
                        }
                        first = false;
                    }
                }
                Console.WriteLine(output);
            }

            foreach (var outerPair in rdpConnections) {
                string output = null;
                bool first = true;
                foreach (var innerPair in outerPair.Value) {
                    if (!(innerPair.Key.Equals(Raw, StringComparison.OrdinalIgnoreCase))) {
                        if (first) {
                            output = innerPair.Value;
                        }
                        else {
                            output = output + " " + innerPair.Value;
                        }
                        first = false;
                    }
                }
                Console.WriteLine(output);
            }

            foreach (var line in unhandledLines) {
                Console.WriteLine(line);
            }

            Console.WriteLine(@"File line count: " + (lines.Length + linesOld.Length));
            Console.WriteLine(@"Headers: " + headerCount);
            Console.WriteLine(@"Log entries: " + logDataCount);
            Console.WriteLine(@"Received/Allowed entries:" + receivedAllowedConnections.Count);
            Console.WriteLine(@"SSH entries: " + sshConnections.Count);
            Console.WriteLine(@"RDP entries: " + rdpConnections.Count);
            Console.WriteLine(@"ICMP entries: " + icmpConnections.Count);
            Console.WriteLine(@"Unhandled entries: " + unhandledLines.Count);
            Console.WriteLine(@"Process time: " + DateTime.Now.Subtract(startTime).ToString(@"hh\:mm\:ss\.fff"));
            Console.WriteLine(@"Press any key to exit.");
            Console.ReadKey();
        }
    }
}
