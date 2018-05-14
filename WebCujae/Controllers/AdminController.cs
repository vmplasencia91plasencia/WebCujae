using System;
using System.Web;
using System.Web.Mvc;
using WebCujae.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Collections.Generic;
using System.Linq;

namespace  WebCujae.Controllers
{
    public class AdminController : Controller
    {
        protected ApplicationDbContext ApplicationDbContext { get; set; }
        protected UserManager<ApplicationUser> UserManager { get; set; }

        public AdminController()
        {
            this.ApplicationDbContext = new ApplicationDbContext();
            this.UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this.ApplicationDbContext));
        }

        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        // POST: /Admin/Index/5
        public ActionResult Index(string notice)
        {
            if (CurrentUser.Get == null)
                return RedirectToAction("Login", "Account");
            else if (CurrentUser.Get.UserName == "admin" && CurrentUser.Get.Email == "admin@cujae.edu.cu")
            {
                return RedirectToAction("UpdateAdminAccount", "Account");
            }
            ViewBag.Notice = notice;
            return View();
        }
        public ActionResult AdminEvento()
        {
            return View();
        }
        public ActionResult AdminPregrado()
        {
            return View();
        }

        [ValidateInput(false)]
        [HttpPost]
        public ActionResult AdminPregrado(CKEditors editors)
        {
            string text = editors.data;
            //ViewData["data"] = text;
            Session["data"] = text;
            return RedirectToAction("Pregrado", "Home");
        }

        [HttpPost]
        public ActionResult File(HttpPostedFileBase file)
        {
            if (file == null)
                return null;
            string archivo = (DateTime.Now.ToString("yyyyMMddHHmmss") + "-" + file.FileName).ToLower();
            file.SaveAs(Server.MapPath("~/Content/img/Uploads/" + archivo));
            return RedirectToAction("Index", "Admin");
        }

        [ValidateInput(false)]
        [HttpPost]
        public ActionResult Index(CKEditors editors)
        {
            string text2 = editors.noticias;
            string text1 = editors.data;
            Session["noticias"] = text2;
            Session["data"] = text1;
            return RedirectToAction("Index", "Admin", new { notice = "Datos Guardados exitosamente!!!!!" });
        }
        // GET: /Admin/Role
        public ActionResult AdminRole()
        {
                return View();
        }
        [HttpPost]
        // POST: /Admin/Role
        public ActionResult AdminRole(List<RolesViewModels> listRole)
        {

            return View();
        }
    }
}