using System;
using System.Linq;

namespace ThreatCrawler
{
    internal class StringOps
    {
        public static string UppercaseFirst(string s)
        {
            if (string.IsNullOrEmpty(s))
            {
                return string.Empty;
            }
            var a = s.ToCharArray();
            a[0] = char.ToUpper(a[0]);
            return new string(a);
        }

        public static string Truncate(string value, int maxChars)
        {
            return value.Length <= maxChars ? value : value.Substring(0, maxChars) + " ...";
        }

        public static string ToFriendlyShortFormat(DateTime time)
        {
            return time.ToString("dd/MM/yyyy");
        }

        public static string FriendlyTimestamp()
        {
            return DateTime.Now.ToString("ddMMyyyy_HHmmss");
        }

        public static string GetExploitUrl(string csvUrl, string exploitUrl)
        {
            var rootUrl = csvUrl.Substring(0, csvUrl.LastIndexOf('/'));
            return rootUrl + "/" + exploitUrl;
        }
    }
}