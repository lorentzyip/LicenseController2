using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LicenseController2.Models
{
    public class LicenseToken
    {
        public Guid Id { get; set; }
        public bool Result { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
