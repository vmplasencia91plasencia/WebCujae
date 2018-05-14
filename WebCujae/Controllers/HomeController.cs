using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebCujae.Controllers
{
    public class HomeController : Controller
    {
        public HomeController()
        {
            
        }
        public ActionResult Index()
        {
            return View();
        }
  
        public ActionResult Pregrado()
        {
            return View();
        }

        public ActionResult Eventos()
        {
            return View();
        }
        public ActionResult Noticias()
        {
            return View();
        }
    }
}