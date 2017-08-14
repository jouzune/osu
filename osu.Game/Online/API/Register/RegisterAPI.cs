using osu.Framework.IO.Network;
using osu.Framework.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace osu.Game.Online.API.Register
{
    public class RegisterAPI
    {
        public string PHPSESSID { get; private set; }
        public string FormGUID { get; private set; }
        public string CFDUID { get; private set; }
        public string LoginCookie { get; private set; }


        private string endpoint;
        public RegisterAPI(string endpoint)
        {
            this.endpoint = endpoint;
        }

        public bool HasRegisterSession => !string.IsNullOrEmpty(FormGUID) && !string.IsNullOrEmpty(PHPSESSID);

        public bool TryGetRegisterSession(out string phpsessid, out string guid, out string cfduid)
        {
            /*
            * GET /p/ register
            * We need the PHPSESSID cookie
            * and the 'v' form parameter
            * for authentication
            */
            var registerRequest = GetRegisterRequest("/p/register", HttpMethod.GET);
            registerRequest.BlockingPerform();

            phpsessid = "";
            guid = "";
            cfduid = "";
            if (registerRequest.Completed)
            {
                // get the value of PHPSESSID cookie
                string setCookie = registerRequest.ResponseHeaders.Get("Set-Cookie");
                var setCookies = setCookie.Split(';');
                foreach (string cookie in setCookies)
                {
                    if (cookie.Contains("PHPSESSID"))
                    {
                        int indexOfEqual = cookie.IndexOf('=');
                        phpsessid = cookie.Substring(indexOfEqual + 1); // don't grab the =
                    }
                    else if (cookie.Contains("cfduid"))
                    {
                        int indexOfEqual = cookie.IndexOf('=');
                        cfduid = cookie.Substring(indexOfEqual + 1);
                    }
                }

                // get the form value of hidden input 'v'
                string responseBody = registerRequest.ResponseString;
                string pattern = "type=[\"']hidden[\"']\\s+name=[\"']v[\"']\\s+value=[\"'](.+)[\"']";
                var match = Regex.Match(responseBody, pattern);
                if (match.Success)
                {
                    guid = match.Groups[1].Value;
                }
                PHPSESSID = phpsessid;
                FormGUID = guid;
                CFDUID = cfduid;
                return true;
            }
            return false;
        }

        public WebRequest GetRegisterRequest(string urlPath, HttpMethod method)
        {
            var url = $"{endpoint}{urlPath}";
            var request = new Framework.IO.Network.WebRequest(url);
            request.Method = method;
            request.EncodedBody = true;

            request.AddHeader("Accept-Encoding", "gzip, deflate, br");
            request.AddHeader("X-Requested-With", "XMLHttpRequest");

            if (method == HttpMethod.POST)
            {
                request.AddHeader("Cookie", $"__cfduid={CFDUID}; PHPSESSID={PHPSESSID}; " + (string.IsNullOrEmpty(LoginCookie) ? "" : LoginCookie));
            }

            return request;
        }

        public Tuple<string, bool> IsValidUserName(string userName)
        {
            var request = GetRegisterRequest("/p/register", HttpMethod.POST);
            request.AddParameter("check", "username");
            request.AddParameter("value", userName);
            request.AddParameter("v", FormGUID);

            request.BlockingPerform();

            if (request.Completed)
            {
                string msg = request.ResponseString;
                bool isValid = msg.Length == 0;
                return Tuple.Create(isValid ? "" : msg, isValid);
            }
            else
            {
                Logger.Log($"Failed to access {endpoint}/p/register", LoggingTarget.Network);
            }

            return Tuple.Create("", false);
        }

        public Tuple<string, bool> IsValidPassword(string password)
        {
            var request = GetRegisterRequest("/p/register", HttpMethod.POST);
            request.AddParameter("check", "password");
            request.AddParameter("value", password);
            request.AddParameter("v", FormGUID);


            request.BlockingPerform();

            if (request.Completed)
            {
                string msg = request.ResponseString;
                bool isValid = msg.Length == 0;
                return Tuple.Create(isValid ? "" : msg, isValid);
            }
            else
            {
                Logger.Log($"Failed to access {endpoint}/p/register", LoggingTarget.Network);
            }

            return Tuple.Create("", false);
        }

        public Tuple<string, bool> IsValidEmail(string email)
        {
            var request = GetRegisterRequest("/p/register", HttpMethod.POST);
            request.AddParameter("check", "email");
            request.AddParameter("value", email);
            request.AddParameter("v", FormGUID);

            request.BlockingPerform();

            if (request.Completed)
            {
                string msg = request.ResponseString;
                bool isValid = msg.Length == 0;
                int indexOf = msg.IndexOf("<a");
                if (indexOf > -1)
                {
                    msg = msg.Substring(0, indexOf);
                }
                return Tuple.Create(isValid ? "" : msg, isValid);
            }
            else
            {
                Logger.Log($"Failed to access {endpoint}/p/register", LoggingTarget.Network);
            }

            return Tuple.Create("", false);
        }
        public bool RegisterUser(string userName, string password, string email)
        {
            var request = GetRegisterRequest("/p/register", HttpMethod.POST);
            request.AddParameter("username", userName);
            request.AddParameter("email", email);
            request.AddParameter("password", password);
            request.AddParameter("v", FormGUID);

            request.BlockingPerform();

            if (request.Completed)
            {
                return true;
            }
            return false;
        }
        public Tuple<string, bool> CheckRegistration()
        {
            var request = GetRegisterRequest("/p/register", HttpMethod.POST);
            request.AddParameter("check", "registration");
            request.AddParameter("v", FormGUID);
            request.EncodedBody = true;

            request.BlockingPerform();
            if (request.Completed)
            {
                string msg = request.ResponseString;
                return Tuple.Create(msg, msg == "complete");
            }

            return Tuple.Create("", false);
        }

        public bool LoginToWebsite(string username, string password)
        {
            var login = GetRegisterRequest("/forum/ucp.php?mode=login", HttpMethod.POST);
            login.EncodedBody = true;
            login.AddParameter("username", username);
            login.AddParameter("password", password);
            login.AddParameter("login", "login");

            login.BlockingPerform();

            if (login.Completed)
            {
                var setCookie = login.ResponseHeaders.Get("Set-Cookie");
                var cookies = setCookie.Split(';');
                LoginCookie = "";
                foreach (var cookie in cookies)
                {
                    if (cookie.Contains("php"))
                    {
                        int indexOf = cookie.IndexOf('=');
                        var phpCookieVa = cookie.Substring(indexOf + 1);
                        LoginCookie = LoginCookie + $"{Regex.Replace(cookie, "HttpOnly,", "")}; ";
                    }
                }
            }

            return login.Completed;
        }

        public bool SendVerificationEmail()
        {
            var request = GetRegisterRequest("/p/verify", HttpMethod.POST);
            request.EncodedBody = true;
            request.AddParameter("v", FormGUID);
            request.AddParameter("check", "forgot");

            request.BlockingPerform();

            return request.Completed;
        }

        public Tuple<string, bool> CheckVerificationCode()
        {
            var login = GetRegisterRequest("/p/verify", HttpMethod.POST);
            login.EncodedBody = true;
            login.AddParameter("value", "regcode12345");
            login.AddParameter("check", "verify");
            login.AddParameter("checkonly", "true");
            login.AddParameter("v", FormGUID);

            login.BlockingPerform();
            if (login.Completed)
            {
                var msg = login.ResponseString;
                return Tuple.Create(msg, msg.Length == 0);
            }
            return Tuple.Create("", false);
        }
    }
}
