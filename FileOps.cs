using System;
using System.IO;
using System.Linq;

namespace ThreatCrawler
{
    internal class FileOps
    {
        public static string[] ProductsToCheck()
        {
            var productArray = File.ReadLines("checklist.txt").ToArray();
            Array.Sort(productArray);
            return productArray;
        }
    }
}