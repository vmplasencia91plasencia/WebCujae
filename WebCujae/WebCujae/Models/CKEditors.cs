using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace WebCujae.Models
{
    public class CKEditors
    {
        [Required]
        public string data { get; set; }
        [Required]
        public string noticias { get; set; }
    }
}