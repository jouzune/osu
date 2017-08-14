using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using osu.Game.Online.API.Register;

namespace osu.Game.Tests.Online
{
    [TestFixture]
    class RegisterAPITests
    {
        private static readonly string endpoint = @"https://osu.ppy.sh";
        [Test]
        public void RegisterSession()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            bool session = api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            Assert.IsTrue(session);
        }

        [Test]
        public void BadPassword()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidPassword("world");
            Assert.IsFalse(tuple.Item2);
        }

        [Test]
        public void GoodPassword()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidPassword("world123456");
            Assert.IsTrue(tuple.Item2);
        }

        [Test]
        public void TakenUsername()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidUserName("hello");
            Assert.AreEqual("This username is already taken!", tuple.Item1);
            Assert.IsFalse(tuple.Item2);
        }

        [Test]
        public void BadUsername()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidUserName("h");
            Assert.AreEqual("The requested username is too short.", tuple.Item1);
            Assert.IsFalse(tuple.Item2);

        }

        [Test]
        public void GoodUsername()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidUserName("ntestacc123");
            Assert.IsTrue(tuple.Item2);
        }

        [Test]
        public void TakenEmail()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidEmail("lunarnublet@gmail.com");
            Assert.AreEqual("The email address is already in use. ", tuple.Item1);
            Assert.IsFalse(tuple.Item2);

        }

        [Test]
        public void BadEmail()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidEmail("asdf");
            Assert.AreEqual("Invalid email address.", tuple.Item1);
            Assert.IsFalse(tuple.Item2);

        }

        [Test]
        public void GoodEmail()
        {
            var api = new RegisterAPI(endpoint);
            string phpsessid;
            string guid;
            string cfduid;
            api.TryGetRegisterSession(out phpsessid, out guid, out cfduid);
            var tuple = api.IsValidEmail("ntestacc123@gmail.com");
            Assert.IsTrue(tuple.Item2);
        }


    }
}
