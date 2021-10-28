using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;

namespace Speed_up_win_10.Pages
{
    public class DownloadModel : PageModel
    {
        public void OnGet(string batch)
        {
            
        }

        public ActionResult OnPost(string batch)
        {
            var contentType = "text/plain";
            var bytes = Encoding.UTF8.GetBytes(batch);
            var result = new FileContentResult(bytes, contentType);
            result.FileDownloadName = "speedup-win-10.bat";
            return result;
        }
    }
}
