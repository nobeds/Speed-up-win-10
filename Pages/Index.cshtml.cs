using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.IO;

namespace Speed_up_win_10.Pages
{
    public class IndexModel : PageModel
    {
        public string script { get; set; }

        public string batch { get; set; }


        public void OnGet()
        {
            
        }

        public void OnPost(IFormCollection form)
        {
            ViewData["batch"] = "";
            script = System.IO.File.ReadAllText("wwwroot/bat/start.bat");
            batch += script + Environment.NewLine;

            foreach (var key in form.Keys)
            {
                if (form[key.ToString()] == "on")
                {
                    script = System.IO.File.ReadAllText("wwwroot/bat/" + key.ToString() + ".bat");
                    batch += script + Environment.NewLine;
                }
            }

            script = System.IO.File.ReadAllText("wwwroot/bat/finish.bat");
            batch += script + Environment.NewLine;

            ViewData["batch"] = batch;
        }

        
    }
}