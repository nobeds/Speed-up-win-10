using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.IO;

namespace Speed_up_win_10.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {

        }
        public string batch { get; set; }
        public string script { get; set; }

        public ActionResult OnPost(IFormCollection form)
        {

            if (form != null)
            {
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
                                
            }

            batch += "echo ##############################################" + Environment.NewLine;
            batch += "pause" + Environment.NewLine;

            var contentType = "text/plain";
            var bytes = Encoding.UTF8.GetBytes(batch);
            var result = new FileContentResult(bytes, contentType);
            result.FileDownloadName = "speedup-win-10.bat";
            return result;
        }
    }
}