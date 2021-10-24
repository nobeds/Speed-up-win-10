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
        public ActionResult OnPost(IFormCollection form)
        {
            if(form == null)
            {
                batch += "echo Speed up win 10 started" + Environment.NewLine;
                batch += "echo ##############################################" + Environment.NewLine;
                batch = "echo Nothing selected";
                batch += "echo ##############################################" + Environment.NewLine;
            }
            else
            {
                batch += "echo Speed up win 10 started" + Environment.NewLine;
                batch += "echo ##############################################" + Environment.NewLine;

                //Disable updates
                if (form["1"].ToString() == "on")
                {
                    batch += "sc config wuauserv start= disable" + Environment.NewLine +
                        "sc config bits start = disable" + Environment.NewLine +
                        "sc config DcomLaunch start = disable" + Environment.NewLine +
                        "net stop wuauserv" + Environment.NewLine +
                        "net stop bits" + Environment.NewLine +
                        "net stop DcomLaunch" + Environment.NewLine;
                }

                //Disable antimalware
                if (form["2"].ToString() == "on")
                {
                    batch += "Taskkill /f /IM msmpeng.exe" + Environment.NewLine+
                        "sc config msmpeng start= disabled" + Environment.NewLine;
                }

                //Disable one drive
                if (form["3"].ToString() == "on")
                {
                    batch += "taskkill /f /im OneDrive.exe" + Environment.NewLine+
                        "%SystemRoot%\\System32\\OneDriveSetup.exe /uninstall"+ Environment.NewLine +
                        "%SystemRoot%\\SysWOW64\\OneDriveSetup.exe /uninstall" + Environment.NewLine;
                }

                //Disable defender
                if (form["4"].ToString() == "on")
                {
                    batch += "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t \"REG_DWORD\" /d \"1\" /f" + Environment.NewLine;
                }

                if (form["disable_cortana"].ToString() == "on")
                {
                    string script = System.IO.File.ReadAllText("wwwroot/bat/disable_cortana.bat");
                    batch += script + Environment.NewLine;
                }

                if (form["disable_win_updates"].ToString() == "on")
                {
                    string script = System.IO.File.ReadAllText("wwwroot/bat/disable_win_updates.bat");
                    batch += script + Environment.NewLine;
                }

                if (form["disable_app_updates"].ToString() == "on")
                {
                    string script = System.IO.File.ReadAllText("wwwroot/bat/disable_app_updates.bat");
                    batch += script + Environment.NewLine;
                }

                if (form["disable_telemetry"].ToString() == "on")
                {
                    string script = System.IO.File.ReadAllText("wwwroot/bat/disable_telemetry.bat");
                    batch += script + Environment.NewLine;
                }

                if (form["disable_services"].ToString() == "on")
                {
                    string script = System.IO.File.ReadAllText("wwwroot/bat/disable_services.bat");
                    batch += script + Environment.NewLine;
                }

                batch += "echo ##############################################" + Environment.NewLine;
                batch += "pause" + Environment.NewLine;

            }

            var contentType = "text/plain";
            var bytes = Encoding.UTF8.GetBytes(batch);
            var result = new FileContentResult(bytes, contentType);
            result.FileDownloadName = "speedup-win-10.bat";
            return result;
        }
    }
}