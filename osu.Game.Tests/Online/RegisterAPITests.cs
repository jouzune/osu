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
        void RegisterSession()
        {
            var api = new RegisterAPI(endpoint);
        }
    }
}
