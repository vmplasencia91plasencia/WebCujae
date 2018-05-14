using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WebCujae.Startup))]
namespace WebCujae
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
