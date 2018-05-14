using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebCujae.Models
{
    public class Data
    {
        public int DataID { get; set; }
        public int type  { get; set; } 
        public string shortDescription { get; set; }
        public string largeDescription { get; set; }
        public DateTime time { get; set; }
        public string title { get; set; }
        public string image_url { get; set; }
        public virtual Site Site { get; set; }
    }
}
