using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace WebCujae.Models
{
    public class RolesViewModels
    {
        public ApplicationUser User { get; set; }
        public bool roleRevisor { get; set; }
        public bool roleRedactor { get; set; }
    }
}