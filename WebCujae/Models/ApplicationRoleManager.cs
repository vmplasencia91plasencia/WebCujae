using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebCujae.Models
{
    public class ApplicationRoleManager : RoleManager<IdentityRole>
    {
        public ApplicationRoleManager(IRoleStore<IdentityRole, string> roleStore)
            : base(roleStore)
        {

        }

        public static IdentityRole CreateAdminRole()
        {
            var roleStore = new RoleStore<IdentityRole>(new ApplicationDbContext());
            var roleManager = new RoleManager<IdentityRole>(roleStore);
            var applicationRoleAdministrator = new IdentityRole("admin");
            if (!roleManager.RoleExists(applicationRoleAdministrator.Name))
            {
                roleManager.Create(applicationRoleAdministrator);
                return applicationRoleAdministrator;
            }
            return roleManager.FindByName("admin");
        }

        public static void CreateRole()
        {
            var roleStore = new RoleStore<IdentityRole>(new ApplicationDbContext());
            var roleManager = new RoleManager<IdentityRole>(roleStore);
            if (!roleManager.RoleExists("redactor") && !roleManager.RoleExists("revisor"))
            {
                var applicationRoleRedactor = new IdentityRole("redactor");
                var applicationRevisor = new IdentityRole("revisor");
                roleManager.Create(applicationRevisor);
                roleManager.Create(applicationRoleRedactor);

            }
        }
          

        public static ApplicationRoleManager Create(IdentityFactoryOptions<ApplicationRoleManager> options, IOwinContext context)
        {
            ApplicationDbContext conte = new ApplicationDbContext();
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(conte));
            var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(conte));
            //return new ApplicationRoleManager(new RoleStore<IdentityRole>(context.Get<ApplicationDbContext>()));
            return new ApplicationRoleManager(new RoleStore<IdentityRole>(new ApplicationDbContext()));
        }
    }
}