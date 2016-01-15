using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using LicenseController2.Models;
using LicenseController2.Helper;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Security.Cryptography;

namespace LicenseController2.Controllers
{
    public class LicenseTokenController : ApiController
    {
        public LicenseToken Get()
        {
            string[] encryptedText;
            LicenseToken token = new LicenseToken { Id = Guid.NewGuid(), Message = "MAC Address错误，请更新授权文件！", Result = false, Timestamp = DateTime.Now };

            try
            {
                encryptedText = File.ReadAllLines(@"C:\license.dat");
                if (encryptedText == null || encryptedText.Length < 1)
                {
                    token.Result = false;
                    token.Message = "授权文件为空，请更新授权文件！";
                    return token;
                }
            }
            catch (Exception e)
            {
                token.Result = false;
                token.Message = "找不到授权文件，请更新授权文件！";
                return token;
            }

            Crypto cryptoHelper = new Crypto();

            byte[] encryptedBytes;
            byte[] passwordBytes;
            byte[] decryptedBytes;
            string decryptedText;

            try {
                encryptedBytes = Convert.FromBase64String(encryptedText[0]);
            } catch (Exception e)
            {
                token.Result = false;
                token.Message = "授权文件内容不对，请更新授权文件！";
                return token;
            }
            passwordBytes = Encoding.UTF8.GetBytes("Lorentz@QWESTRO");
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            decryptedBytes = cryptoHelper.AES_Decrypt(encryptedBytes, passwordBytes);
            decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            if (decryptedText.Length != 21)
            {
                token.Result = false;
                token.Message = "授权文件内容不对，请更新授权文件！";
                return token;
            }

            string macAddress = "";
            string expiryDateStr = "";

            try
            {
                macAddress = decryptedText.Substring(0, 12);
                expiryDateStr = decryptedText.Substring(13);
            }
            catch (Exception e)
            {
                token.Result = false;
                token.Message = "授权文件格式不对，请更新授权文件！";
                return token;
            }

            DateTime localDate = DateTime.Now;
            DateTime expiryDate;

            try {
                expiryDate = DateTime.ParseExact(expiryDateStr, "ddMMyyyy", null);
            } catch
            {
                token.Result = false;
                token.Message = "日期格式不对，请更新授权文件！";
                return token;
            }

            IPGlobalProperties computerProperties = IPGlobalProperties.GetIPGlobalProperties();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();

            if (nics == null || nics.Length < 1)
            {
                token.Result = false;
                token.Message = "没有网卡，必须安装网卡运行！";
                return token;
            }

            foreach (NetworkInterface adapter in nics)
            {
                if (!String.Equals(adapter.NetworkInterfaceType.ToString(), "ethernet", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                PhysicalAddress address = adapter.GetPhysicalAddress();

                if (String.Equals(address.ToString(), macAddress, StringComparison.OrdinalIgnoreCase))
                {
                    if (DateTime.Compare(localDate, expiryDate) <= 0)
                    {
                        token.Result = true;
                        token.Message = macAddress;
                    }
                    else
                    {
                        token.Result = false;
                        token.Message = "授权文件已经过期（" + expiryDate.ToString() + "），请更新授权文件！";
                    }
                }
            }

            return token;
        }
    }
}
