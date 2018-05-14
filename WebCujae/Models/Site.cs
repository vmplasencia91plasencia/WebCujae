using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace WebCujae.Models
{
    public class Site
    {
        [Key]
        public int SiteID { get; set; }
        public string name { get; set; }
        public virtual ICollection<Data> Datas { get; set; }

        public virtual Undergraduate Undergraduate { get; set; }
    }
}
