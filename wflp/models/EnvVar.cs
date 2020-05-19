namespace wflp
{
    public class EnvVar
    {
        public string DataDirectory;
        public string DataFile;
        public string DataFileCopy;
        public string OldDataFile;
        public string OldDataFileCopy;

        public EnvVar(bool useDefault)
        {
            if (useDefault)
            {
                this.DataDirectory = @"%SystemRoot%\System32\LogFiles\Firewall";
                this.DataFile = @"pfirewall.log";
                this.DataFileCopy = @"pfirewall - Copy.log";
                this.OldDataFile = @"pfirewall.log.old";
                this.OldDataFileCopy = @"pfirewall.log - Copy.old";
            }
        }
    }
}
