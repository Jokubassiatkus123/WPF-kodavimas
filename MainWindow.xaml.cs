using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Microsoft.Win32;

namespace FileEncryptionApp
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string inputFile = ChooseFile();
            if (inputFile != null)
            {
                try
                {
                    SecureString password = PasswordBox.SecurePassword;
                    EncryptFile(inputFile, password);
                    MessageBox.Show("Failas uzkoduotas!");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Užkodavimas nepavyko.: {ex.Message}", "Klaida", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string inputFile = ChooseFile();
            if (inputFile != null)
            {
                try
                {
                    SecureString password = PasswordBox.SecurePassword;
                    DecryptFile(inputFile, password);
                    MessageBox.Show("Failas atkoduotas!");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Atkodaivmas nepavyko: {ex.Message}", "Klaida", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string ChooseFile()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                return openFileDialog.FileName;
            }
            return null;
        }
        private string ConvertSecureStringToString(SecureString secureString)
        {
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        private void EncryptFile(string inputFile, SecureString password)
        {
            byte[] salt = GenerateSalt();

            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                string passwordString = ConvertSecureStringToString(password);
                Rfc2898DeriveBytes keyDerivationFunction = new Rfc2898DeriveBytes(passwordString, salt);
                aesAlg.Key = keyDerivationFunction.GetBytes(aesAlg.KeySize / 8);

                aesAlg.GenerateIV();

                using (FileStream fsCrypt = new FileStream(inputFile + ".uzkoduota", FileMode.Create))
                {
                    fsCrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                    using (CryptoStream cs = new CryptoStream(fsCrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
                        {
                            byte[] buffer = new byte[1048576]; // 1 MB
                            int read;

                            while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                cs.Write(buffer, 0, read);
                            }
                        }
                    }
                }
            }
        }

        private void DecryptFile(string inputFile, SecureString password)
        {
            byte[] salt = GenerateSalt();

            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                string passwordString = ConvertSecureStringToString(password);
                Rfc2898DeriveBytes keyDerivationFunction = new Rfc2898DeriveBytes(passwordString, salt);
                aesAlg.Key = keyDerivationFunction.GetBytes(aesAlg.KeySize / 8);

                using (FileStream fsCrypt = new FileStream(inputFile, FileMode.Open))
                {
                    byte[] iv = new byte[aesAlg.BlockSize / 8];
                    fsCrypt.Read(iv, 0, iv.Length);

                    aesAlg.IV = iv;

                    using (CryptoStream cs = new CryptoStream(fsCrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (FileStream fsOut = new FileStream(inputFile.Replace(".atkoduota", ""), FileMode.Create))
                        {
                            byte[] buffer = new byte[1048576]; // 1 MB
                            int read;

                            while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                fsOut.Write(buffer, 0, read);
                            }
                        }
                    }
                }
            }
        }

        private byte[] GenerateSalt()
        {
            byte[] salt = new byte[16]; // 128 bits
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(salt);
            }
            return salt;
        }
    }
}
