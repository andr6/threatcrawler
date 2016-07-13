using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web.UI;

namespace ThreatCrawler
{
    internal class ReportingOps
    {
        public static string GenerateHtmlReport(List<Item> CertAlertItems, List<Item> MalwareItems, List<Item> NvdItems,
            List<ItemWithoutSummary> ZeroDayItems,
            List<Item> BugTraqItems, List<Item> FullDisclosureItems, List<Item> PacketStormItems, List<Item> ZdiItems)
        {
            using (var writer = new StringWriter())
            {
                using (var html = new HtmlTextWriter(writer))
                {
                    html.RenderBeginTag(HtmlTextWriterTag.Html);

                    html.AddAttribute(HtmlTextWriterAttribute.Style, "font-family:sans-serif;");
                    html.RenderBeginTag(HtmlTextWriterTag.Body);

                    html.AddAttribute(HtmlTextWriterAttribute.Name, "top");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.RenderBeginTag(HtmlTextWriterTag.H1);
                    html.WriteEncodedText("ThreatCrawler Vulnerability Update");
                    html.RenderEndTag();
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.H3);
                    html.WriteEncodedText(DateTime.Now.ToString("d"));
                    html.RenderEndTag();

                    html.WriteBreak();
                    html.RenderBeginTag(HtmlTextWriterTag.H2);
                    html.WriteEncodedText("Summary");
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.P);

                    if (CertAlertItems.Count > 0)
                    {
                        var certAlertCount = CertAlertItems.Count;

                        html.AddAttribute(HtmlTextWriterAttribute.Href, "#CERT_Alerts");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText("CERT Alerts");
                        html.RenderEndTag();
                        html.WriteEncodedText(string.Format(": {0}", certAlertCount));
                        html.WriteBreak();
                    }

                    if (MalwareItems.Count > 0)
                    {
                        var malwareCount = MalwareItems.Count;

                        html.AddAttribute(HtmlTextWriterAttribute.Href, "#Malware");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText("Malware");
                        html.RenderEndTag();
                        html.WriteEncodedText(string.Format(": {0}", malwareCount));
                        html.WriteBreak();
                    }

                    var products = FileOps.ProductsToCheck();
                    var lastItem = products.Last();

                    foreach (var product in products)
                    {
                        var nvdCount = NvdItems.Count(i => i.Category.ToLower() == product.ToLower());
                        var zeroDayCount = ZeroDayItems.Count(i => i.Category.ToLower() == product.ToLower());
                        var bugTraqCount = BugTraqItems.Count(i => i.Category.ToLower() == product.ToLower());
                        var fullDisclosureCount =
                            FullDisclosureItems.Count(i => i.Category.ToLower() == product.ToLower());
                        var packetStormCount = PacketStormItems.Count(i => i.Category.ToLower() == product.ToLower());
                        var zdiCount = ZdiItems.Count(i => i.Category.ToLower() == product.ToLower());

                        var totalCount = nvdCount + zeroDayCount + bugTraqCount + fullDisclosureCount + packetStormCount +
                                         zdiCount;

                        if (totalCount <= 0)
                        {
                            continue;
                        }

                        html.AddAttribute(HtmlTextWriterAttribute.Href, string.Format("#{0}", product));
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText(StringOps.UppercaseFirst(product));
                        html.RenderEndTag();
                        html.WriteEncodedText(string.Format(": {0}", totalCount));

                        if (product != lastItem)
                        {
                            html.WriteBreak();
                        }
                    }

                    html.RenderEndTag();

                    if (CertAlertItems.Count > 0)
                    {
                        html.WriteBreak();
                        html.AddAttribute(HtmlTextWriterAttribute.Name, "CERT_Alerts");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.RenderBeginTag(HtmlTextWriterTag.H2);
                        html.WriteEncodedText("CERT Alerts");
                        html.RenderEndTag();
                        html.RenderEndTag();

                        foreach (var item in CertAlertItems)
                        {
                            html.RenderBeginTag(HtmlTextWriterTag.P);
                            html.RenderBeginTag(HtmlTextWriterTag.H4);
                            html.WriteEncodedText(item.Title);
                            html.RenderEndTag();
                            html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                            html.WriteBreak();
                            html.AddAttribute(HtmlTextWriterAttribute.Style,
                                "background: #f5f5fb;border-left: 10px solid #ccc;padding: 1px 10px 15px 10px;");
                            html.RenderBeginTag(HtmlTextWriterTag.Blockquote);
                            html.Write(item.Content);
                            html.RenderEndTag();
                            html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                            html.RenderBeginTag(HtmlTextWriterTag.A);
                            html.WriteEncodedText("View Alert");
                            html.RenderEndTag();
                            html.RenderEndTag();
                        }

                        html.AddAttribute(HtmlTextWriterAttribute.Href, "#top");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText("Back to Top");
                        html.RenderEndTag();
                    }

                    if (MalwareItems.Count > 0)
                    {
                        html.WriteBreak();
                        html.AddAttribute(HtmlTextWriterAttribute.Name, "Malware");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.RenderBeginTag(HtmlTextWriterTag.H2);
                        html.WriteEncodedText("New Malware");
                        html.RenderEndTag();
                        html.RenderEndTag();

                        html.AddAttribute(HtmlTextWriterAttribute.Style,
                            "background: #f5f5fb;border-left: 10px solid #ccc;padding: 1px 10px 15px 10px;");
                        html.RenderBeginTag(HtmlTextWriterTag.Blockquote);

                        foreach (var item in MalwareItems)
                        {
                            html.RenderBeginTag(HtmlTextWriterTag.P);
                            html.RenderBeginTag(HtmlTextWriterTag.H4);
                            html.WriteEncodedText(item.Title);
                            html.RenderEndTag();
                            html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                            html.WriteBreak();
                            html.Write(item.Content);
                            html.WriteBreak();
                            html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                            html.RenderBeginTag(HtmlTextWriterTag.A);
                            html.WriteEncodedText("Read More");
                            html.RenderEndTag();
                            html.RenderEndTag();
                        }

                        html.AddAttribute(HtmlTextWriterAttribute.Href, "#top");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText("Back to Top");
                        html.RenderEndTag();

                        html.RenderEndTag();
                    }

                    foreach (var product in products)
                    {
                        var nvdItems = NvdItems.Where(i => i.Category.ToLower() == product.ToLower()).ToList();
                        var zeroDayItems = ZeroDayItems.Where(i => i.Category.ToLower() == product.ToLower()).ToList();
                        var bugTraqItems = BugTraqItems.Where(i => i.Category.ToLower() == product.ToLower()).ToList();
                        var fullDisclosureItems =
                            FullDisclosureItems.Where(i => i.Category.ToLower() == product.ToLower()).ToList();
                        var packetStormItems =
                            PacketStormItems.Where(i => i.Category.ToLower() == product.ToLower()).ToList();
                        var zdiItems =
                            ZdiItems.Where(i => i.Category.ToLower() == product.ToLower()).ToList();

                        if (nvdItems.Count <= 0 && zeroDayItems.Count <= 0 && bugTraqItems.Count <= 0 &&
                            fullDisclosureItems.Count <= 0 && packetStormItems.Count <= 0 && zdiItems.Count <= 0)
                        {
                            continue;
                        }

                        html.WriteBreak();
                        html.AddAttribute(HtmlTextWriterAttribute.Name, product);
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.RenderBeginTag(HtmlTextWriterTag.H2);
                        html.WriteEncodedText(string.Format("Hits for '{0}'", product));
                        html.RenderEndTag();
                        html.RenderEndTag();

                        html.AddAttribute(HtmlTextWriterAttribute.Style,
                            "background: #f5f5fb;border-left: 10px solid #ccc;padding: 1px 10px 15px 10px;");
                        html.RenderBeginTag(HtmlTextWriterTag.Blockquote);

                        if (zeroDayItems.Count > 0)
                        {
                            foreach (var item in zeroDayItems)
                            {
                                html.RenderBeginTag(HtmlTextWriterTag.P);
                                html.RenderBeginTag(HtmlTextWriterTag.H4);
                                html.WriteEncodedText(item.Title);
                                html.RenderEndTag();
                                html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                                html.WriteBreak();
                                html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                                html.RenderBeginTag(HtmlTextWriterTag.A);
                                html.WriteEncodedText("Read More");
                                html.RenderEndTag();
                                html.RenderEndTag();
                            }
                        }

                        if (bugTraqItems.Count > 0)
                        {
                            foreach (var item in bugTraqItems)
                            {
                                html.RenderBeginTag(HtmlTextWriterTag.P);
                                html.RenderBeginTag(HtmlTextWriterTag.H4);
                                html.WriteEncodedText(item.Title);
                                html.RenderEndTag();
                                html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                                html.WriteBreak();
                                html.Write(item.Content);
                                html.WriteBreak();
                                html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                                html.RenderBeginTag(HtmlTextWriterTag.A);
                                html.WriteEncodedText("Read More");
                                html.RenderEndTag();
                                html.RenderEndTag();
                            }
                        }

                        if (fullDisclosureItems.Count > 0)
                        {
                            foreach (var item in fullDisclosureItems)
                            {
                                html.RenderBeginTag(HtmlTextWriterTag.P);
                                html.RenderBeginTag(HtmlTextWriterTag.H4);
                                html.WriteEncodedText(item.Title);
                                html.RenderEndTag();
                                html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                                html.WriteBreak();
                                html.Write(item.Content);
                                html.WriteBreak();
                                html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                                html.RenderBeginTag(HtmlTextWriterTag.A);
                                html.WriteEncodedText("Read More");
                                html.RenderEndTag();
                                html.RenderEndTag();
                            }
                        }

                        if (nvdItems.Count > 0)
                        {
                            foreach (var item in nvdItems)
                            {
                                html.RenderBeginTag(HtmlTextWriterTag.P);
                                html.RenderBeginTag(HtmlTextWriterTag.H4);
                                html.WriteEncodedText(item.Title);
                                html.RenderEndTag();
                                html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                                html.WriteBreak();
                                html.Write(item.Content);
                                html.WriteBreak();
                                html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                                html.RenderBeginTag(HtmlTextWriterTag.A);
                                html.WriteEncodedText("Read More");
                                html.RenderEndTag();
                                html.RenderEndTag();
                            }
                        }

                        if (packetStormItems.Count > 0)
                        {
                            foreach (var item in packetStormItems)
                            {
                                html.RenderBeginTag(HtmlTextWriterTag.P);
                                html.RenderBeginTag(HtmlTextWriterTag.H4);
                                html.WriteEncodedText(item.Title);
                                html.RenderEndTag();
                                html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                                html.WriteBreak();
                                html.Write(item.Content);
                                html.WriteBreak();
                                html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                                html.RenderBeginTag(HtmlTextWriterTag.A);
                                html.WriteEncodedText("Read More");
                                html.RenderEndTag();
                                html.RenderEndTag();
                            }
                        }

                        if (zdiItems.Count > 0)
                        {
                            foreach (var item in zdiItems)
                            {
                                html.RenderBeginTag(HtmlTextWriterTag.P);
                                html.RenderBeginTag(HtmlTextWriterTag.H4);
                                html.WriteEncodedText(item.Title);
                                html.RenderEndTag();
                                html.WriteEncodedText(string.Format("Published: {0}", item.PublishDate));
                                html.WriteBreak();
                                html.Write(item.Content);
                                html.WriteBreak();
                                html.AddAttribute(HtmlTextWriterAttribute.Href, item.Link);
                                html.RenderBeginTag(HtmlTextWriterTag.A);
                                html.WriteEncodedText("Read More");
                                html.RenderEndTag();
                                html.RenderEndTag();
                            }
                        }

                        html.AddAttribute(HtmlTextWriterAttribute.Href, "#top");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText("Back to Top");
                        html.RenderEndTag();

                        html.RenderEndTag();
                    }

                    html.WriteBreak();
                    html.RenderBeginTag(HtmlTextWriterTag.H2);
                    html.WriteEncodedText("Sources");
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.P);

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "http://0day.today");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("0day.today");
                    html.RenderEndTag();
                    html.WriteBreak();

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "http://seclists.org/bugtraq/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("BugTraq");
                    html.RenderEndTag();
                    html.WriteBreak();

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "http://seclists.org/fulldisclosure/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("Full Disclosure Mailing List");
                    html.RenderEndTag();
                    html.WriteBreak();

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "https://nvd.nist.gov/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("NIST National Vulnerability Database");
                    html.RenderEndTag();
                    html.WriteBreak();

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "https://packetstormsecurity.com/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("Packet Storm Security");
                    html.RenderEndTag();
                    html.WriteBreak();

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "https://www.symantec.com/security_response/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("Symantec Security Response");
                    html.RenderEndTag();
                    html.WriteBreak();

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "https://www.trendmicro.com/us/about-us/rss-feeds/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("Trend Micro Security Intelligence");
                    html.RenderEndTag();
                    html.WriteBreak();

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "http://www.zerodayinitiative.com/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("Zero Day Initiative");
                    html.RenderEndTag();

                    html.RenderEndTag();

                    html.WriteBreak();
                    html.RenderBeginTag(HtmlTextWriterTag.H2);
                    html.WriteEncodedText("Search Terms");
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.P);

                    foreach (var product in products)
                    {
                        html.Write(product != lastItem ? string.Format("{0}, ", product) : product);
                    }

                    html.RenderEndTag();

                    html.RenderEndTag();
                    html.RenderEndTag();
                }

                return writer.ToString();
            }
        }

        public static string GenerateHtmlExploitList(List<Exploit> ExploitList)
        {
            using (var writer = new StringWriter())
            {
                using (var html = new HtmlTextWriter(writer))
                {
                    html.RenderBeginTag(HtmlTextWriterTag.Html);

                    html.AddAttribute(HtmlTextWriterAttribute.Style, "font-family:sans-serif;");
                    html.RenderBeginTag(HtmlTextWriterTag.Body);

                    html.Write("<style>");
                    html.Write("table {width: 100%; border-collapse: collapse;padding: 1px 10px 15px 10px;}");
                    html.Write("th {display: table-cell;vertical-align: inherit;font-weight: bold;text-align: center;}");
                    html.Write("tr:nth-child(even) {background-color: #f2f2f2}");
                    html.Write("</style>");

                    html.AddAttribute(HtmlTextWriterAttribute.Name, "top");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.RenderBeginTag(HtmlTextWriterTag.H1);
                    html.WriteEncodedText("ThreatCrawler Exploit Report");
                    html.RenderEndTag();
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.H3);
                    html.WriteEncodedText(DateTime.Now.ToString("d"));
                    html.RenderEndTag();

                    html.WriteBreak();
                    html.RenderBeginTag(HtmlTextWriterTag.H2);
                    html.WriteEncodedText("Summary");
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.P);

                    var products = FileOps.ProductsToCheck();
                    var lastItem = products.Last();

                    foreach (var product in products)
                    {
                        var exploitCount = ExploitList.Count(i => i.Category.ToLower() == product.ToLower());

                        if (exploitCount <= 0)
                        {
                            continue;
                        }

                        html.AddAttribute(HtmlTextWriterAttribute.Href, string.Format("#{0}", product));
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText(StringOps.UppercaseFirst(product));
                        html.RenderEndTag();
                        html.WriteEncodedText(string.Format(": {0}", exploitCount));

                        if (product != lastItem)
                        {
                            html.WriteBreak();
                        }
                    }

                    foreach (var product in products)
                    {
                        var items = ExploitList.Where(i => i.Category.ToLower() == product.ToLower()).ToList();

                        if (items.Count <= 0)
                        {
                            continue;

                        }

                        html.WriteBreak();
                        html.AddAttribute(HtmlTextWriterAttribute.Name, product);
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.RenderBeginTag(HtmlTextWriterTag.H2);
                        html.WriteEncodedText(string.Format("Exploits for for '{0}'", product));
                        html.RenderEndTag();
                        html.RenderEndTag();

                        html.RenderBeginTag(HtmlTextWriterTag.Table);
                        
                        html.RenderBeginTag(HtmlTextWriterTag.Tr);
                        html.RenderBeginTag(HtmlTextWriterTag.Th);
                        html.WriteEncodedText("Description");
                        html.RenderEndTag();
                        html.RenderBeginTag(HtmlTextWriterTag.Th);
                        html.WriteEncodedText("Date");
                        html.RenderEndTag();
                        html.RenderBeginTag(HtmlTextWriterTag.Th);
                        html.WriteEncodedText("Type");
                        html.RenderEndTag();
                        html.RenderBeginTag(HtmlTextWriterTag.Th);
                        html.WriteEncodedText("Platform");
                        html.RenderEndTag();
                        html.RenderBeginTag(HtmlTextWriterTag.Th);
                        html.WriteEncodedText("Port");
                        html.RenderEndTag();
                        html.RenderBeginTag(HtmlTextWriterTag.Th);
                        html.WriteEncodedText("Link");
                        html.RenderEndTag();
                        html.RenderEndTag();

                        foreach (var item in items)
                        {
                            html.RenderBeginTag(HtmlTextWriterTag.Tr);

                            html.RenderBeginTag(HtmlTextWriterTag.Td);
                            html.WriteEncodedText(item.Description);
                            html.RenderEndTag();

                            html.RenderBeginTag(HtmlTextWriterTag.Td);
                            html.WriteEncodedText(StringOps.ToFriendlyShortFormat(item.PublishDate));
                            html.RenderEndTag();

                            html.RenderBeginTag(HtmlTextWriterTag.Td);
                            html.WriteEncodedText(item.Type);
                            html.RenderEndTag();

                            html.RenderBeginTag(HtmlTextWriterTag.Td);
                            html.WriteEncodedText(item.Platform);
                            html.RenderEndTag();

                            html.RenderBeginTag(HtmlTextWriterTag.Td);
                            html.WriteEncodedText(item.Port);
                            html.RenderEndTag();

                            html.RenderBeginTag(HtmlTextWriterTag.Td);
                            html.AddAttribute(HtmlTextWriterAttribute.Href, item.Url);
                            html.RenderBeginTag(HtmlTextWriterTag.A);
                            html.WriteEncodedText("Read More");
                            html.RenderEndTag();
                            html.RenderEndTag();

                            html.RenderEndTag();
                        }

                        html.RenderEndTag();

                        html.WriteBreak();
                        html.AddAttribute(HtmlTextWriterAttribute.Href, "#top");
                        html.RenderBeginTag(HtmlTextWriterTag.A);
                        html.WriteEncodedText("Back to Top");
                        html.RenderEndTag();
                        html.WriteBreak();
                    }

                    html.WriteBreak();
                    html.WriteBreak();
                    html.WriteBreak();
                    html.RenderBeginTag(HtmlTextWriterTag.H2);
                    html.WriteEncodedText("Sources");
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.P);

                    html.AddAttribute(HtmlTextWriterAttribute.Href, "https://www.exploit-db.com/");
                    html.RenderBeginTag(HtmlTextWriterTag.A);
                    html.WriteEncodedText("Exploit Database");
                    html.RenderEndTag();

                    html.RenderEndTag();

                    html.WriteBreak();
                    html.RenderBeginTag(HtmlTextWriterTag.H2);
                    html.WriteEncodedText("Search Terms");
                    html.RenderEndTag();

                    html.RenderBeginTag(HtmlTextWriterTag.P);

                    foreach (var product in products)
                    {
                        html.Write(product != lastItem ? string.Format("{0}, ", product) : product);
                    }

                    html.RenderEndTag();

                    html.RenderEndTag();
                    html.RenderEndTag();
                }

                return writer.ToString();
            }
        }
    }
}