using System;

namespace AngelMineChecker
{
    public class ScanOptions
    {
        public bool CheckCortex { get; set; } = true;
        public bool CheckSystemDlc { get; set; } = true;
        public bool CheckDoomsday { get; set; } = true;
        public bool CheckLuminar { get; set; } = true;
    }
}
