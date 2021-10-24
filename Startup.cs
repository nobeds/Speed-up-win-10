namespace Speed_up_win_10
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.  
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews().AddRazorRuntimeCompilation();
        }
    }
}
