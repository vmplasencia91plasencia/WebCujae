
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using System.Security.Claims;
using Newtonsoft.Json;

namespace WebCujae.Models
{
    public class CurrentUser
    {
        public string UserId { get; set; }
        public  string Name { get; set; }
        public  string LastName { get; set; }
        public  string Email { get; set; }
        public  string UserName { get; set; }
        public string NumberIdentification { get; set; }
        public static bool EmailConfirmed { get; set; }

        public static CurrentUser Get
        {
            get{
                var user = HttpContext.Current.User;
                if (user == null)
                {
                    return null;
                }
                else if (string.IsNullOrEmpty(user.Identity.GetUserId()))
                {
                    return null;
                }
                var juser = ((ClaimsIdentity)user.Identity).FindFirst(ClaimTypes.UserData).Value;
                return JsonConvert.DeserializeObject<CurrentUser>(juser);
            }
        }
    }
}