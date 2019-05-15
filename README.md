![image](https://www.lucas-cueff.com/files/gallery.png)
# Manage-TrustedPublisher
Simple powershell module to manage code signing certificate in trusted publisher container on Windows computers and servers

(c) 2018-2019 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## install Manage-TrustedPublisher from PowerShell Gallery repository
You can easily install it from powershell gallery repository
https://www.powershellgallery.com/packages/Manage-TrustedPublisher/
using a simple powershell command and an internet access :-) 
```
	Install-Module -Name Manage-TrustedPublisher
```
## import module from PowerShell 
```	
	.EXAMPLE
	C:\PS> import-module Manage-TrustedPublisher.psd1
  
```
## module content
### Import-TrustedPublisherCert function
 ```
 		.SYNOPSIS 
		import a certificate file in the trusted publisher container of the local machine certificate store
	
		.DESCRIPTION
		import a certificate file in the trusted publisher container of the local machine certificate store
	
		.PARAMETER certfile
		Mandatory parameter
		-certfile certfile{full file path to a valid CER file}
	
		.OUTPUTS
		   TypeName : System.Security.Cryptography.X509Certificates.X509Certificate2

			Name                            MemberType     Definition
			----                            ----------     ----------
			Dispose                         Method         void Dispose(), void IDisposable.Dispose()
			Equals                          Method         bool Equals(System.Object obj), bool Equals(X509Certificate other)
			Export                          Method         byte[] Export(System.Security.Cryptography.X509Certificates.X509Conte...
			GetCertHash                     Method         byte[] GetCertHash()
			GetCertHashString               Method         string GetCertHashString()
			GetEffectiveDateString          Method         string GetEffectiveDateString()
			GetExpirationDateString         Method         string GetExpirationDateString()
			GetFormat                       Method         string GetFormat()
			GetHashCode                     Method         int GetHashCode()
			GetIssuerName                   Method         string GetIssuerName()
			GetKeyAlgorithm                 Method         string GetKeyAlgorithm()
			GetKeyAlgorithmParameters       Method         byte[] GetKeyAlgorithmParameters()
			GetKeyAlgorithmParametersString Method         string GetKeyAlgorithmParametersString()
			GetName                         Method         string GetName()
			GetNameInfo                     Method         string GetNameInfo(System.Security.Cryptography.X509Certificates.X509...
			GetObjectData                   Method         void ISerializable.GetObjectData(System.Runtime.Serialization.Seriali...
			GetPublicKey                    Method         byte[] GetPublicKey()
			GetPublicKeyString              Method         string GetPublicKeyString()
			GetRawCertData                  Method         byte[] GetRawCertData()
			GetRawCertDataString            Method         string GetRawCertDataString()
			GetSerialNumber                 Method         byte[] GetSerialNumber()
			GetSerialNumberString           Method         string GetSerialNumberString()
			GetType                         Method         type GetType()
			Import                          Method         void Import(byte[] rawData), void Import(byte[] rawData, string passw...
			OnDeserialization               Method         void IDeserializationCallback.OnDeserialization(System.Object sender)
			Reset                           Method         void Reset()
			ToString                        Method         string ToString(), string ToString(bool verbose)
			Verify                          Method         bool Verify()
			Archived                        Property       bool Archived {get;set;}
			Extensions                      Property       System.Security.Cryptography.X509Certificates.X509ExtensionCollection...
			FriendlyName                    Property       string FriendlyName {get;set;}
			Handle                          Property       System.IntPtr Handle {get;}
			HasPrivateKey                   Property       bool HasPrivateKey {get;}
			Issuer                          Property       string Issuer {get;}
			IssuerName                      Property       X500DistinguishedName IssuerName {get;}
			NotAfter                        Property       datetime NotAfter {get;}
			NotBefore                       Property       datetime NotBefore {get;}
			PrivateKey                      Property       System.Security.Cryptography.AsymmetricAlgorithm PrivateKey {get;set;}
			PublicKey                       Property       System.Security.Cryptography.X509Certificates.PublicKey PublicKey {get;}
			RawData                         Property       byte[] RawData {get;}
			SerialNumber                    Property       string SerialNumber {get;}
			SignatureAlgorithm              Property       System.Security.Cryptography.Oid SignatureAlgorithm {get;}
			Subject                         Property       string Subject {get;}
			SubjectName                     Property       X500DistinguishedName SubjectName {get;}
			Thumbprint                      Property       string Thumbprint {get;}
			Version                         Property       int Version {get;}
			DnsNameList                     ScriptProperty System.Object DnsNameList {get=,(new-object Microsoft.Powershell.Comm...
			EnhancedKeyUsageList            ScriptProperty System.Object EnhancedKeyUsageList {get=,(new-object Microsoft.Powers...
			SendAsTrustedIssuer             ScriptProperty System.Object SendAsTrustedIssuer {get=[Microsoft.Powershell.Commands...
	
		.EXAMPLE
		add certificatessign.cer to the Trusted Publisher container of the local machine certificate store
		C:\PS> Import-TrustedPublisherCert -certfile "c:\test\certificatessign.cer"
 ```
 ### Remove-TrustedPublisherCert function
 ```
 		.SYNOPSIS 
		Remove a certificate from the trusted publisher container of the local machine certificate store
	
		.DESCRIPTION
		Remove a certificate from the trusted publisher container of the local machine certificate store
	
		.PARAMETER certfile
		-certfile certfile{full file path to a valid CER file}

		.PARAMETER thumbprint
		-thumbprint string{valid thumbprint of a certificate already installed in the trusted published container}
	
		.OUTPUTS
		   TypeName : System.Security.Cryptography.X509Certificates.X509Certificate2

		   	Name                            MemberType     Definition
			----                            ----------     ----------
			Dispose                         Method         void Dispose(), void IDisposable.Dispose()
			Equals                          Method         bool Equals(System.Object obj), bool Equals(X509Certificate other)
			Export                          Method         byte[] Export(System.Security.Cryptography.X509Certificates.X509Conte...
			GetCertHash                     Method         byte[] GetCertHash()
			GetCertHashString               Method         string GetCertHashString()
			GetEffectiveDateString          Method         string GetEffectiveDateString()
			GetExpirationDateString         Method         string GetExpirationDateString()
			GetFormat                       Method         string GetFormat()
			GetHashCode                     Method         int GetHashCode()
			GetIssuerName                   Method         string GetIssuerName()
			GetKeyAlgorithm                 Method         string GetKeyAlgorithm()
			GetKeyAlgorithmParameters       Method         byte[] GetKeyAlgorithmParameters()
			GetKeyAlgorithmParametersString Method         string GetKeyAlgorithmParametersString()
			GetName                         Method         string GetName()
			GetNameInfo                     Method         string GetNameInfo(System.Security.Cryptography.X509Certificates.X509...
			GetObjectData                   Method         void ISerializable.GetObjectData(System.Runtime.Serialization.Seriali...
			GetPublicKey                    Method         byte[] GetPublicKey()
			GetPublicKeyString              Method         string GetPublicKeyString()
			GetRawCertData                  Method         byte[] GetRawCertData()
			GetRawCertDataString            Method         string GetRawCertDataString()
			GetSerialNumber                 Method         byte[] GetSerialNumber()
			GetSerialNumberString           Method         string GetSerialNumberString()
			GetType                         Method         type GetType()
			Import                          Method         void Import(byte[] rawData), void Import(byte[] rawData, string passw...
			OnDeserialization               Method         void IDeserializationCallback.OnDeserialization(System.Object sender)
			Reset                           Method         void Reset()
			ToString                        Method         string ToString(), string ToString(bool verbose)
			Verify                          Method         bool Verify()
			Archived                        Property       bool Archived {get;set;}
			Extensions                      Property       System.Security.Cryptography.X509Certificates.X509ExtensionCollection...
			FriendlyName                    Property       string FriendlyName {get;set;}
			Handle                          Property       System.IntPtr Handle {get;}
			HasPrivateKey                   Property       bool HasPrivateKey {get;}
			Issuer                          Property       string Issuer {get;}
			IssuerName                      Property       X500DistinguishedName IssuerName {get;}
			NotAfter                        Property       datetime NotAfter {get;}
			NotBefore                       Property       datetime NotBefore {get;}
			PrivateKey                      Property       System.Security.Cryptography.AsymmetricAlgorithm PrivateKey {get;set;}
			PublicKey                       Property       System.Security.Cryptography.X509Certificates.PublicKey PublicKey {get;}
			RawData                         Property       byte[] RawData {get;}
			SerialNumber                    Property       string SerialNumber {get;}
			SignatureAlgorithm              Property       System.Security.Cryptography.Oid SignatureAlgorithm {get;}
			Subject                         Property       string Subject {get;}
			SubjectName                     Property       X500DistinguishedName SubjectName {get;}
			Thumbprint                      Property       string Thumbprint {get;}
			Version                         Property       int Version {get;}
			DnsNameList                     ScriptProperty System.Object DnsNameList {get=,(new-object Microsoft.Powershell.Comm...
			EnhancedKeyUsageList            ScriptProperty System.Object EnhancedKeyUsageList {get=,(new-object Microsoft.Powers...
			SendAsTrustedIssuer             ScriptProperty System.Object SendAsTrustedIssuer {get=[Microsoft.Powershell.Commands...
	
		.EXAMPLE
		Remove certificatessign.cer from the Trusted Publisher container of the local machine certificate store
		C:\PS> Remove-TrustedPublisherCert -certfile "c:\test\certificatessign.cer"

		.EXAMPLE
		remove certificate with thumprint xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx from the Trusted Publisher container of local machine certificate store
		C:\PS> Check-TrustedPublisherCert -thumbprint "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
 ```
 ### Check-TrustedPublisherCert function
 ```
		.SYNOPSIS 
		check if a certificate is installed in the trusted publisher container of the local machine certificate store
	
		.DESCRIPTION
		check if a certificate is installed in the trusted publisher container of the local machine certificate store
	
		.PARAMETER certfile
		-certfile certfile{full file path to a valid CER file}

		.PARAMETER thumbprint
		-thumbprint string{valid thumbprint of a certificate already installed in the trusted published container}
	
		.OUTPUTS
		TypeName : boolean
	
		.EXAMPLE
		check if certificatessign.cer is already added in Trusted Publisher container of local machine certificate store
		C:\PS> Check-TrustedPublisherCert -certfile "c:\test\certificatessign.cer"

		.EXAMPLE
		check if certificate with thumprint xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx is already added in Trusted Publisher container of local machine certificate store
		C:\PS> Check-TrustedPublisherCert -thumbprint "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  ``` 
