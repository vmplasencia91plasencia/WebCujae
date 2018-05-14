using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace WebCujae.Models
{
    public class Undergraduate
    {
        [ForeignKey("Site")]
        public int UndergraduateID { get; set; }
        public string fulltext { get; set; }
        public virtual Site Site { get; set; }
    }
}
