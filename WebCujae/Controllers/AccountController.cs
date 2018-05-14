using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using WebCujae.Models;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

namespace WebCujae.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController()
        {

        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }
        public ActionResult SignOut()
        {
            var AuthenticationManager = HttpContext.GetOwinContext().Authentication;
            AuthenticationManager.SignOut();
           // ViewBag.ReturnUrl = returnUrl;
            return RedirectToAction("Login","Account");
        }
        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = UserManager.Find(model.UserName, model.Password);
            if (user != null)
            {
                if (!await UserManager.IsEmailConfirmedAsync(user.Id))
                {
                    ViewBag.errorMessage = "Debe tener un correo electrónico confirmado para iniciar sesión." +
                                          "El token de confirmación ha sido reenviado a su cuenta de correo electrónico.";
                    return View("Error");
                }
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    var data = UserManager.Find(model.UserName,model.Password);
                    var juser = JsonConvert.SerializeObject(new CurrentUser {
                        Email=data.Email,
                        Name=data.Name,
                        LastName=data.LastName,
                        UserName=data.UserName,
                        UserId=data.Id,
                        NumberIdentification=data.NumberIdentification
                    });
                    if (data.Email == "admin@cujae.edu.cu")
                    {
                        var userClaims=UserManager.GetClaims(CurrentUser.Get.UserId);
                        if (userClaims.Any())
                        {
                            foreach (var item in userClaims)
                            {
                                UserManager.RemoveClaim(CurrentUser.Get.UserId, item);
                            }
                        }
                    }
                        await UserManager.AddClaimAsync(data.Id, new Claim(ClaimTypes.UserData, juser));
                    return RedirectToAction("Index", "Admin");
                case SignInStatus.LockedOut:
                    return View("Lockout");
                default:
                    ModelState.AddModelError("", "Intento de inicio de sesión inválido");
                    return View(model);
            }
        }

        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser() {
                    Name = model.Name,
                    LastName = model.LastName,
                    Email = model.Email,
                    UserName = model.UserName,
                    NumberIdentification = model.NumberIdentification,
                    EmailConfirmed = false   
                };
            
            var result = await UserManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                // Confirmar correo.
                System.Net.Mail.MailMessage m = new System.Net.Mail.MailMessage(
                new System.Net.Mail.MailAddress("vmplasencia@tesla.cujae.edu.cu", "Web Registration"),
                new System.Net.Mail.MailAddress(user.Email));
                m.Subject = "Email confirmation";
                m.Body = string.Format("Dear {0}<BR/>Thank you for your registration, please click on the below link to complete your registration: <a href=\"{1}\" title=\"User Email Confirm\">{1}</a>", user.UserName, Url.Action("ConfirmEmail", "Account", new { Token = user.Id, Email = user.Email }, Request.Url.Scheme));
                m.IsBodyHtml = true;
                System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("tesla.cujae.edu.cu");
                smtp.Credentials = new System.Net.NetworkCredential("vmplasencia@tesla.cujae.edu.cu", "Badday16.");
                smtp.EnableSsl = false;
                smtp.Send(m);

                return RedirectToAction("Login", "Account");
            }
            AddErrors(result);
        }

            // If we got this far, something failed, redisplay form
            return View(model);
    }
        // GET: /Account/UpdateAdminAccount
        [AllowAnonymous]
        public ActionResult UpdateAdminAccount()
        {
            return View();
        }

        //
        // POST: /Account/UpdateAdminAccount
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult UpdateAdminAccount(UpdateAdminAccountViewModel model)
        {
            if (ModelState.IsValid)
            {
                HashAlgorithm algorithm = MD5.Create();
                algorithm.ComputeHash(Encoding.UTF8.GetBytes(model.Password));
                string id = CurrentUser.Get.UserId;
                ApplicationUser user = UserManager.FindById(id);
                user.Name = model.Name;
                user.LastName = model.LastName;
                user.Email = model.Email;
                user.NumberIdentification = model.NumberIdentification;
                user.EmailConfirmed = true;
               // user.PasswordHash=algorithm.ToString()
           
                var result = UserManager.Update(user);
                if (result.Succeeded) {
                    var data = UserManager.FindById(id);
                    var juser = JsonConvert.SerializeObject(new CurrentUser
                    {
                        Email = data.Email,
                        Name = data.Name,
                        LastName = data.LastName,
                        UserName = data.UserName,
                        UserId = data.Id,
                        NumberIdentification = data.NumberIdentification
                    });
                    //UserManager.RemoveClaim(id, new Claim(ClaimTypes.UserData, juser));
                    //UserManager.AddClaim(id, new Claim(ClaimTypes.UserData, juser));
                    return RedirectToAction("Login", "Account");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [AllowAnonymous]
    public ActionResult Confirm(string Email)
    {
        ViewBag.Email = Email;
        return View();
    }
        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
    public async Task<ActionResult> ConfirmEmail(string Token, string Email)
    {
        ApplicationUser user = this.UserManager.FindById(Token);
        if (user != null)
        {
            if (user.Email == Email)
            {
                user.EmailConfirmed = true;
                await UserManager.UpdateAsync(user);
                await SignInAsync(user, isPersistent: false);
                return RedirectToAction("Login", "Account");
            }
            else
            {
                return RedirectToAction("Confirm", "Account", new { Email = user.Email });
            }
        }
        else
        {
            return RedirectToAction("Confirm", "Account", new { Email = "" });
        }

    }
    //
    // GET: /Account/ForgotPassword
    [AllowAnonymous]
    public ActionResult ForgotPassword()
    {
        return View();
    }

    //
    // POST: /Account/ForgotPassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await UserManager.FindByEmailAsync(model.Email);
            if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return View("ForgotPasswordConfirmation");
            }

            // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
             //Send an email with this link
             string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
             var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
             //await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");

                System.Net.Mail.MailMessage m = new System.Net.Mail.MailMessage(
                   new System.Net.Mail.MailAddress("vmplasencia@tesla.cujae.edu.cu", "Forgot Password"),
                   new System.Net.Mail.MailAddress(user.Email));
                m.Subject = "Forgot Password";
                m.Body = string.Format("Hello you have forgotten your password , Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                m.IsBodyHtml = true;
                System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("tesla.cujae.edu.cu");
                smtp.Credentials = new System.Net.NetworkCredential("vmplasencia@tesla.cujae.edu.cu", "Badday16.");
                smtp.EnableSsl = false;
                smtp.Send(m);
                return RedirectToAction("ForgotPasswordConfirmation", "Account");
        }

        // If we got this far, something failed, redisplay form
        return View(model);
    }

    //
    // GET: /Account/ForgotPasswordConfirmation
    [AllowAnonymous]
    public ActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    //
    // GET: /Account/ResetPassword
    [AllowAnonymous]
    public ActionResult ResetPassword(string code)
    {
        return code == null ? View("Error") : View();
    }

    //
    // POST: /Account/ResetPassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }
        var user = await UserManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            // Don't reveal that the user does not exist
            return RedirectToAction("ResetPasswordConfirmation", "Account");
        }
        var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
        if (result.Succeeded)
        {
            return RedirectToAction("ResetPasswordConfirmation", "Account");
        }
        AddErrors(result);
        return View();
    }

    //
    // GET: /Account/ResetPasswordConfirmation
    [AllowAnonymous]
    public ActionResult ResetPasswordConfirmation()
    {
        return View();
    }

    //
    // POST: /Account/ExternalLogin
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public ActionResult ExternalLogin(string provider, string returnUrl)
    {
        // Request a redirect to the external login provider
        return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
    }

    //
    // GET: /Account/SendCode
    [AllowAnonymous]
    public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
    {
        var userId = await SignInManager.GetVerifiedUserIdAsync();
        if (userId == null)
        {
            return View("Error");
        }
        var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
        var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
        return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
    }

    //
    // POST: /Account/SendCode
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> SendCode(SendCodeViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }

        // Generate the token and send it
        if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
        {
            return View("Error");
        }
        return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
    }

    //
    // GET: /Account/ExternalLoginCallback
    [AllowAnonymous]
    public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
    {
        var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
        if (loginInfo == null)
        {
            return RedirectToAction("Login");
        }

        // Sign in the user with this external login provider if the user already has a login
        var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
        switch (result)
        {
            case SignInStatus.Success:
                return RedirectToLocal(returnUrl);
            case SignInStatus.LockedOut:
                return View("Lockout");
            case SignInStatus.RequiresVerification:
                return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
            case SignInStatus.Failure:
            default:
                // If the user does not have an account, then prompt the user to create an account
                ViewBag.ReturnUrl = returnUrl;
                ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
        }
    }

    //
    // POST: /Account/ExternalLoginConfirmation
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
    {
        if (User.Identity.IsAuthenticated)
        {
            return RedirectToAction("Index", "Manage");
        }

        if (ModelState.IsValid)
        {
            // Get the information about the user from the external login provider
            var info = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return View("ExternalLoginFailure");
            }
            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await UserManager.CreateAsync(user);
            if (result.Succeeded)
            {
                result = await UserManager.AddLoginAsync(user.Id, info.Login);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                    return RedirectToLocal(returnUrl);
                }
            }
            AddErrors(result);
        }

        ViewBag.ReturnUrl = returnUrl;
        return View(model);
    }

    //
    // POST: /Account/LogOff
    [HttpPost]
    [ValidateAntiForgeryToken]
    public ActionResult LogOff()
    {
        AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
        return RedirectToAction("Index", "Home");
    }

    //
    // GET: /Account/ExternalLoginFailure
    [AllowAnonymous]
    public ActionResult ExternalLoginFailure()
    {
        return View();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (_userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            if (_signInManager != null)
            {
                _signInManager.Dispose();
                _signInManager = null;
            }
        }

        base.Dispose(disposing);
    }

    private async Task SignInAsync(ApplicationUser user, bool isPersistent)
    {
        AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
        var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
        AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
    }

    #region Helpers
    // Used for XSRF protection when adding external logins
    private const string XsrfKey = "XsrfId";

    private IAuthenticationManager AuthenticationManager
    {
        get
        {
            return HttpContext.GetOwinContext().Authentication;
        }
    }

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError("", error);
        }
    }

    private ActionResult RedirectToLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return RedirectToAction("Index", "Home");
    }

    internal class ChallengeResult : HttpUnauthorizedResult
    {
        public ChallengeResult(string provider, string redirectUri)
            : this(provider, redirectUri, null)
        {
        }

        public ChallengeResult(string provider, string redirectUri, string userId)
        {
            LoginProvider = provider;
            RedirectUri = redirectUri;
            UserId = userId;
        }

        public string LoginProvider { get; set; }
        public string RedirectUri { get; set; }
        public string UserId { get; set; }

        public override void ExecuteResult(ControllerContext context)
        {
            var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
            if (UserId != null)
            {
                properties.Dictionary[XsrfKey] = UserId;
            }
            context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
        }
    }
    #endregion
}
}