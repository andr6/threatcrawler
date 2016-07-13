using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net;
using System.ServiceModel.Syndication;
using System.Text.RegularExpressions;
using System.Xml;

namespace ThreatCrawler
{
    internal class Program
    {
        private static readonly string CertAlertUri = ConfigurationManager.AppSettings["CERT Alerts URI"];
        private static readonly string SymantecAlertUri = ConfigurationManager.AppSettings["Symantec URI"];
        private static readonly string TrendAlertUri = ConfigurationManager.AppSettings["Trend URI"];
        private static readonly string ZeroDayUri = ConfigurationManager.AppSettings["0day.today URI"];
        private static readonly string BugTraqUri = ConfigurationManager.AppSettings["BugTraq URI"];
        private static readonly string FullDisclosureUri = ConfigurationManager.AppSettings["Full Disclosure URI"];
        private static readonly string NvdUri = ConfigurationManager.AppSettings["NVD URI"];
        private static readonly string PacketStormUri = ConfigurationManager.AppSettings["Packet Storm URI"];
        private static readonly string ZdiUri = ConfigurationManager.AppSettings["ZDI URI"];

        private static readonly string ExploitDbCSV = ConfigurationManager.AppSettings["Exploit DB CSV"];

        private static readonly int BulletinDaysToCheck = Convert.ToInt32(ConfigurationManager.AppSettings["Bulletin Days to Check"]);
        private static readonly int ExploitDaysToCheck = Convert.ToInt32(ConfigurationManager.AppSettings["Exploit Days to Check"]);

        private static void Main(string[] args)
        {
            Console.WriteLine("Checking CERT alerts...");
            var certAlertItems = GetCertAlerts();

            Console.WriteLine("Checking Symantec...");
            var symantecItems = GetSymantecAlerts();

            Console.WriteLine("Checking Trend...");
            var trendItems = GetTrendAlerts();

            var malwareItems = symantecItems.Concat(trendItems).ToList();

            Console.WriteLine("Checking 0day.today...");
            var zeroDayItems = GetZeroDayItems();

            Console.WriteLine("Checking BugTraq...");
            var bugTraqItems = GetBugTraqItems();

            Console.WriteLine("Checking Full Disclosure...");
            var fullDisclosureItems = GetFullDisclosureItems();

            Console.WriteLine("Checking NVD...");
            var nvdItems = GetNvdItems();

            Console.WriteLine("Checking Packet Storm...");
            var packetStormItems = GetPacketStormItems();

            Console.WriteLine("Checking Zero Day Initiative...");
            var zdiItems = GetZdiItems();

            Console.WriteLine("Compiling Exploit Archive...");

            var exploitList = GetExploitArchive();

            Console.WriteLine("Preparing Report...");

            var vulnReport = ReportingOps.GenerateHtmlReport(certAlertItems, malwareItems, nvdItems, zeroDayItems,
                bugTraqItems, fullDisclosureItems, packetStormItems, zdiItems);

            if (exploitList.Count > 0)
            {
                var exploitReport = ReportingOps.GenerateHtmlExploitList(exploitList);

                Console.WriteLine("Sending email...");

                MailOps.SendEmailWithAttachment(vulnReport, exploitReport);
            }

            else
            {
                Console.WriteLine("Sending email...");

                MailOps.SendEmail(vulnReport);
            }

            Console.WriteLine("Done!");
            Console.ReadLine();
        }


        private static List<Item> GetCertAlerts()
        {
            var reader = XmlReader.Create(CertAlertUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            if (feed == null)
            {
                return null;
            }

            return (from item in feed.Items
                where item.PublishDate.LocalDateTime >= DateTime.Now.AddDays(-BulletinDaysToCheck)
                select new Item
                {
                    Title = item.Title.Text, PublishDate = item.PublishDate.LocalDateTime, Content = item.Summary.Text, Category = "alert", Link = item.Links[0].Uri.ToString()
                }).ToList();
        }

        private static List<Item> GetSymantecAlerts()
        {
            var reader = XmlReader.Create(SymantecAlertUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            if (feed == null)
            {
                return null;
            }

            return (from item in feed.Items
                    where item.PublishDate.LocalDateTime >= DateTime.Now.AddDays(-BulletinDaysToCheck)
                    select new Item
                    {
                        Title = item.Title.Text,
                        PublishDate = item.PublishDate.LocalDateTime,
                        Content = item.Summary.Text,
                        Category = "malware",
                        Link = item.Links[0].Uri.ToString()
                    }).ToList();
        }

        private static List<Item> GetTrendAlerts()
        {
            var reader = XmlReader.Create(TrendAlertUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            if (feed == null)
            {
                return null;
            }

            return (from item in feed.Items
                    where item.PublishDate.LocalDateTime >= DateTime.Now.AddDays(-BulletinDaysToCheck)
                    select new Item
                    {
                        Title = item.Title.Text,
                        PublishDate = item.PublishDate.LocalDateTime,
                        Content = item.Summary.Text,
                        Category = "malware",
                        Link = item.Links[0].Uri.ToString()
                    }).ToList();
        }

        private static List<ItemWithoutSummary> GetZeroDayItems()
        {
            var reader = XmlReader.Create(ZeroDayUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            var list = new List<ItemWithoutSummary>();

            if (feed == null)
            {
                return null;
            }

            foreach (var item in feed.Items)
            {
                list.AddRange(from product in FileOps.ProductsToCheck()
                    where Regex.IsMatch(item.Title.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase)
                    select new ItemWithoutSummary
                    {
                        Title = item.Title.Text,
                        PublishDate = item.PublishDate.LocalDateTime,
                        Link = item.Links[0].Uri.ToString(),
                        Category = product
                    });
            }

            return list;
        }

        private static List<Item> GetBugTraqItems()
        {
            var reader = XmlReader.Create(BugTraqUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            var list = new List<Item>();

            if (feed == null)
            {
                return null;
            }

            foreach (var item in feed.Items)
            {
                list.AddRange(from product in FileOps.ProductsToCheck()
                    where
                        Regex.IsMatch(item.Title.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase) ||
                        Regex.IsMatch(item.Summary.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase)
                    select new Item
                    {
                        Title = item.Title.Text,
                        PublishDate = item.PublishDate.LocalDateTime,
                        Content = item.Summary.Text,
                        Link = item.Links[0].Uri.ToString(),
                        Category = product
                    });
            }

            return list;
        }

        private static List<Item> GetFullDisclosureItems()
        {
            var reader = XmlReader.Create(FullDisclosureUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            var list = new List<Item>();

            if (feed == null)
            {
                return null;
            }

            foreach (var item in feed.Items)
            {
                list.AddRange(from product in FileOps.ProductsToCheck()
                    where
                        Regex.IsMatch(item.Title.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase) ||
                        Regex.IsMatch(item.Summary.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase)
                    select new Item
                    {
                        Title = item.Title.Text,
                        PublishDate = item.PublishDate.LocalDateTime,
                        Content = item.Summary.Text,
                        Link = item.Links[0].Uri.ToString(),
                        Category = product
                    });
            }

            return list;
        }

        private static List<Item> GetNvdItems()
        {
            var parser = new ParsingOps.FeedParser();
            var items = parser.Parse(NvdUri, ParsingOps.FeedType.RDF);

            var list = new List<Item>();
            
            foreach (var item in items)
            {
                list.AddRange(from product in FileOps.ProductsToCheck()
                    where Regex.IsMatch(item.Title, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase) ||
                          Regex.IsMatch(item.Content, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase)
                    select new Item
                    {
                        Title = item.Title,
                        PublishDate = item.PublishDate,
                        Content = item.Content,
                        Link = item.Link,
                        Category = product
                    });
            }

            return list;
        }

        private static List<Item> GetPacketStormItems()
        {
            var reader = XmlReader.Create(PacketStormUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            var list = new List<Item>();

            if (feed == null)
            {
                return null;
            }

            foreach (var item in feed.Items)
            {
                list.AddRange(from product in FileOps.ProductsToCheck()
                    where
                        Regex.IsMatch(item.Title.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase) ||
                        Regex.IsMatch(item.Summary.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase)
                    select new Item
                    {
                        Title = item.Title.Text,
                        PublishDate = item.PublishDate.LocalDateTime,
                        Content = item.Summary.Text,
                        Link = item.Links[0].Uri.ToString(),
                        Category = product
                    });
            }

            return list;
        }

        private static List<Item> GetZdiItems()
        {
            var reader = XmlReader.Create(ZdiUri);
            var feed = SyndicationFeed.Load(reader);
            reader.Close();

            var list = new List<Item>();

            if (feed == null)
            {
                return null;
            }

            foreach (var item in feed.Items)
            {
                list.AddRange(from product in FileOps.ProductsToCheck()
                              where
                                  Regex.IsMatch(item.Title.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase) ||
                                  Regex.IsMatch(item.Summary.Text, string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase)
                              select new Item
                              {
                                  Title = item.Title.Text,
                                  PublishDate = item.PublishDate.LocalDateTime,
                                  Content = item.Summary.Text,
                                  Link = item.Links[0].Uri.ToString(),
                                  Category = product
                              });
            }

            return list;
        }

        private static List<Exploit> GetExploitArchive()
        {
            var list = new List<Exploit>();

            using (var client = new WebClient())
            {
                var doc = client.DownloadString(ExploitDbCSV);
                var docLines = doc.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None);

                foreach (var line in docLines)
                {
                    var data = line.Split(',');

                    if (data.Length != 8 || Array.IndexOf(docLines, line) == 0)
                    {
                        continue;
                    }

                    var date = DateTime.ParseExact(data[3], "yyyy-MM-dd", CultureInfo.InvariantCulture);

                    list.AddRange(from product in FileOps.ProductsToCheck()
                        where
                            Regex.IsMatch(data[2], string.Format("\\b{0}\\b", product), RegexOptions.IgnoreCase) &&
                            date >= DateTime.Now.AddDays(-ExploitDaysToCheck)
                                  select new Exploit
                        {
                            Id = data[0],
                            Url = StringOps.GetExploitUrl(ExploitDbCSV, data[1]),
                            Description = data[2],
                            Category = product,
                            PublishDate = date,
                            Platform = StringOps.UppercaseFirst(data[5]),
                            Type = StringOps.UppercaseFirst(data[6]),
                            Port = data[7]
                        });
                }

                return list;
            }
        } 
    }
}